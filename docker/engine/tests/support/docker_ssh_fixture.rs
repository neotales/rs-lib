//! Disposable Debian SSH server with access to the real host Docker socket.

use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

const OWNER_LABEL: &str = "io.neotales.docker-ssh-test.owner";

pub(super) struct DockerFixture {
    owner: String,
    image: String,
    image_id: Option<String>,
    container: String,
    container_id: Option<String>,
    pub(super) password: Zeroizing<String>,
    pub(super) port: u16,
}

impl DockerFixture {
    pub(super) fn start(
        directory: &Path,
        password: Zeroizing<String>,
        password_auth: bool,
    ) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        let owner = format!("{}-{nonce}", std::process::id());
        let mut fixture = Self {
            image: format!("ndocker-ssh-test:{owner}"),
            container: format!("ndocker-ssh-test-{owner}"),
            owner,
            image_id: None,
            container_id: None,
            password,
            port: 0,
        };
        let context =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../eng/ci/ssh-docker-fixture-debian");
        let image_id = directory.join("image-id");
        let output = Command::new("timeout")
            .args(["--kill-after=5s", "600s", "docker"])
            .args(["build", "--label"])
            .arg(format!("{OWNER_LABEL}={}", fixture.owner))
            .arg("--iidfile")
            .arg(&image_id)
            .arg("--tag")
            .arg(&fixture.image)
            .arg(&context)
            .output()
            .expect("build Debian SSH fixture");
        assert_success("build Debian SSH fixture", &output);
        fixture.image_id = Some(
            std::fs::read_to_string(image_id)
                .expect("read built image ID")
                .trim()
                .to_owned(),
        );

        let output = Self::command(&[
            "create",
            "--name",
            &fixture.container,
            "--label",
            &format!("{OWNER_LABEL}={}", fixture.owner),
            "--publish",
            "127.0.0.1::22",
            "--volume",
            "/var/run/docker.sock:/var/run/docker.sock",
            &fixture.image,
        ]);
        assert_success("create Debian SSH fixture", &output);
        fixture.container_id = Some(
            String::from_utf8(output.stdout)
                .expect("container ID is UTF-8")
                .trim()
                .to_owned(),
        );

        fixture.install_credentials(directory, &context, password_auth);
        assert_success(
            "start Debian SSH fixture",
            &Self::command(&["start", &fixture.container]),
        );

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let log = fixture.logs();
            if log.contains("ssh-docker-fixture: ready") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Debian SSH fixture did not become ready:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let output = Self::command(&["port", &fixture.container, "22/tcp"]);
        assert_success("inspect fixture port", &output);
        let published = String::from_utf8(output.stdout).expect("published port is UTF-8");
        fixture.port = published
            .trim()
            .strip_prefix("127.0.0.1:")
            .expect("fixture port binds only to loopback")
            .parse()
            .expect("valid fixture port");
        fixture
    }

    fn install_credentials(&self, directory: &Path, context: &Path, password_auth: bool) {
        // docker cp streams credentials through the API. Bind mounts cannot see
        // the caller's private /tmp namespace and must not expose host secrets.
        let password_file = directory.join("container-password");
        let password_record = Zeroizing::new(format!("{}\n", self.password.as_str()));
        std::fs::write(&password_file, password_record.as_bytes())
            .expect("write private container password");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600))
                .expect("restrict container password file");
        }
        self.copy(
            &directory.join("authorized_keys"),
            "/run/ssh-fixture/authorized_keys",
        );
        self.copy(&password_file, "/run/ssh-fixture/password");
        std::fs::remove_file(password_file).expect("remove staged container password");

        // Keep the server's accepted mechanism identical to the host fixture;
        // a password test must not silently authenticate with its public key.
        let config = directory.join("container-sshd_config");
        let mut text = std::fs::read_to_string(context.join("sshd_config"))
            .expect("read Debian fixture SSH configuration");
        if password_auth {
            text = text.replace("PubkeyAuthentication yes", "PubkeyAuthentication no");
        } else {
            text = text.replace("PasswordAuthentication yes", "PasswordAuthentication no");
        }
        std::fs::write(&config, text).expect("write single-mechanism SSH configuration");
        self.copy(&config, "/etc/ssh/sshd_config");
    }

    fn command(args: &[&str]) -> Output {
        Command::new("timeout")
            .args(["--kill-after=5s", "30s", "docker"])
            .args(args)
            .output()
            .expect("run Docker fixture command")
    }

    fn copy(&self, source: &Path, destination: &str) {
        let output = Command::new("timeout")
            .args(["--kill-after=5s", "30s", "docker"])
            .arg("cp")
            .arg(source)
            .arg(format!("{}:{destination}", self.container))
            .output()
            .expect("stream fixture file into container");
        assert_success("copy fixture file", &output);
    }

    pub(super) fn logs(&self) -> String {
        let output = Self::command(&["logs", &self.container]);
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    fn remove_owned(&self, kind: &str, name: &str, expected: Option<&str>) -> Result<(), String> {
        let format = format!("{{{{.Id}}}}\t{{{{index .Config.Labels \"{OWNER_LABEL}\"}}}}");
        let output = Self::command(&[kind, "inspect", "--format", &format, name]);
        if !output.status.success() {
            if expected.is_none()
                && String::from_utf8_lossy(&output.stderr)
                    .contains(&format!("No such {kind}: {name}"))
            {
                return Ok(());
            }
            return Err(format!("cannot verify owned {kind} {name} before removal"));
        }
        let actual =
            String::from_utf8(output.stdout).map_err(|_| "invalid Docker inspect output")?;
        let record = actual
            .strip_suffix('\n')
            .ok_or("invalid Docker inspect record")?;
        let (id, owner) = record
            .split_once('\t')
            .ok_or("invalid Docker inspect fields")?;
        let hex = if kind == "image" {
            id.strip_prefix("sha256:").ok_or("invalid image ID")?
        } else {
            id
        };
        if hex.len() != 64
            || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            || owner != self.owner
            || expected.is_some_and(|expected| expected != id)
        {
            return Err(format!(
                "refusing to remove {kind} {name}: ID or ownership label changed"
            ));
        }
        let output = if kind == "container" {
            Self::command(&["container", "rm", "--force", id])
        } else {
            Self::command(&["image", "rm", id])
        };
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("failed to remove owned {kind} {name}"))
        }
    }
}

impl Drop for DockerFixture {
    fn drop(&mut self) {
        let mut failures = Vec::new();
        for result in [
            self.remove_owned("container", &self.container, self.container_id.as_deref()),
            self.remove_owned("image", &self.image, self.image_id.as_deref()),
        ] {
            if let Err(error) = result {
                failures.push(error);
            }
        }
        if !failures.is_empty() {
            let message = format!("Docker SSH fixture cleanup failed: {}", failures.join("; "));
            if std::thread::panicking() {
                eprintln!("{message}");
            } else {
                panic!("{message}");
            }
        }
    }
}

fn assert_success(operation: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{operation} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
