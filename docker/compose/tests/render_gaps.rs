//! The eight differences between this renderer's output and Docker's, one test
//! each, with the measurement that settled what the model had to record.
//!
//! Every expectation in this file was captured from `docker compose config` and
//! `docker stack config` on Docker 29.8.0 with Compose v5.5.1, and the capture is
//! quoted in the test that uses it so a future reader can tell a stale expectation
//! from a wrong one.

use neotales_docker_compose::{
    ComposeConfigRenderer, ComposeMountSubtree, ComposeProject, ComposeProjectOptions,
    ComposeRenderOptions, ComposeUlimit, InterpolationValues,
};

/// Loads a document with every profile active, which is what the `config`
/// command's default is for a document that gates a service.
fn load(source: &str) -> ComposeProject {
    ComposeProject::parse_yaml(
        source,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions {
            profiles: ["*".to_owned()].into_iter().collect(),
            ..ComposeProjectOptions::default()
        },
    )
    .expect("the document loads")
}

fn compose(source: &str) -> String {
    ComposeConfigRenderer::render_yaml(&load(source))
}

fn stack(source: &str) -> String {
    ComposeConfigRenderer::render_stack_yaml_with(&load(source), &ComposeRenderOptions::default())
}

/// Renders with the paths resolved against a directory, which is what makes a
/// relative bind distinguishable from a named volume.
fn compose_in(source: &str, directory: &str) -> String {
    ComposeConfigRenderer::render_yaml_with(
        &load(source),
        &ComposeRenderOptions {
            project_directory: Some(std::path::Path::new(directory)),
        },
    )
}

/// Gap 1 — `ports[].mode`. Already modelled; this pins it so a later change
/// cannot quietly drop the member Compose prints unconditionally.
///
/// Measured on 29.8 against a document declaring one short-form and one
/// long-form port:
///
/// ```text
///     ports:
///       - mode: ingress
///         target: 80
///         published: "8080"
///         protocol: tcp
///       - mode: host
///         target: 90
///         published: "9090"
///         protocol: tcp
/// ```
#[test]
fn ports_print_the_mode_even_when_it_is_the_default() {
    let rendered = compose(concat!(
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    ports:\n",
        "      - 8080:80\n",
        "      - target: 90\n",
        "        published: \"9090\"\n",
        "        mode: host\n",
    ));
    assert_eq!(
        rendered,
        concat!(
            "name: gaps\n",
            "services:\n",
            "  a:\n",
            "    image: busybox\n",
            "    networks:\n",
            "      default: null\n",
            "    ports:\n",
            "      - mode: ingress\n",
            "        target: 80\n",
            "        published: \"8080\"\n",
            "        protocol: tcp\n",
            "      - mode: host\n",
            "        target: 90\n",
            "        published: \"9090\"\n",
            "        protocol: tcp\n",
            "networks:\n",
            "  default:\n",
            "    name: gaps_default\n",
        )
    );
}

/// Gap 6 — `published` is a string in the specification and a number in v3.
///
/// Measured on 29.8, same document, two commands:
///
/// ```text
/// $ docker compose config              $ docker stack config
///       - mode: ingress                  - mode: ingress
///         target: 80                       target: 80
///         published: "8080"                 published: 8080
/// ```
#[test]
fn published_is_a_string_in_the_spec_and_a_number_in_v3() {
    let source = concat!(
        "version: \"3.9\"\n",
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    ports:\n",
        "      - 8080:80\n",
    );
    assert!(
        compose(source).contains("        published: \"8080\"\n"),
        "the specification render quotes it:\n{}",
        compose(source)
    );
    assert!(
        stack(source).contains("        published: 8080\n"),
        "the v3 render does not:\n{}",
        stack(source)
    );
}

/// Gap 2, `configs` half — a short-form reference prints no `target`.
///
/// Measured on 29.8 against a service declaring `configs: [c1]` alongside
/// `configs: [{source: c2, target: renamed}]`:
///
/// ```text
///     configs:
///       - source: c1
///       - source: c2
///         target: renamed
/// ```
///
/// The model used to default `target` to the referenced key, which made the two
/// spellings one value and forced the short form to print a key the document
/// never wrote.
#[test]
fn a_short_form_config_reference_prints_no_target() {
    let rendered = compose(concat!(
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    configs:\n",
        "      - c1\n",
        "      - source: c2\n",
        "        target: renamed\n",
        "configs:\n",
        "  c1: {file: ./a.txt}\n",
        "  c2: {file: ./a.txt}\n",
    ));
    assert_eq!(
        rendered,
        concat!(
            "name: gaps\n",
            "services:\n",
            "  a:\n",
            "    configs:\n",
            "      - source: c1\n",
            "      - source: c2\n",
            "        target: renamed\n",
            "    image: busybox\n",
            "    networks:\n",
            "      default: null\n",
            "networks:\n",
            "  default:\n",
            "    name: gaps_default\n",
            "configs:\n",
            "  c1:\n",
            "    name: gaps_c1\n",
            // The file is relative and no directory was given, so it stays as
            // written — the same as Docker with no project directory to resolve
            // it against.
            "    file: ./a.txt\n",
            "  c2:\n",
            "    name: gaps_c2\n",
            "    file: ./a.txt\n",
        )
    );
}

/// Gap 2, `secrets` half — the two schemas disagree about the short form, and
/// both are right for themselves.
///
/// Measured on 29.8, `secrets: [s1]`:
///
/// ```text
/// $ docker compose config          $ docker stack config
///   secrets:                          secrets:
///     - source: s1                      - source: s1
///       target: /run/secrets/s1
/// ```
///
/// The specification render has to name the file, because the mount lands in
/// `/run/secrets/` and a rendered document that did not say where would not be
/// loadable into the same place. v3 prints only what was written.
///
/// This is the case that decided the model shape: the *default* is a property of
/// the renderer that prints it, not of the document, so `target` is an `Option`
/// carrying the written form and each dialect decides what to print for `None`.
#[test]
fn a_short_form_secret_reference_names_the_file_only_in_the_specification() {
    let source = concat!(
        "version: \"3.9\"\n",
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    secrets:\n",
        "      - s1\n",
        "      - source: s2\n",
        "        target: renamed\n",
        "secrets:\n",
        "  s1: {file: ./a.txt}\n",
        "  s2: {file: ./a.txt}\n",
    );
    assert_eq!(
        compose(source),
        concat!(
            "name: gaps\n",
            "services:\n",
            "  a:\n",
            "    image: busybox\n",
            "    networks:\n",
            "      default: null\n",
            "    secrets:\n",
            "      - source: s1\n",
            "        target: /run/secrets/s1\n",
            "      - source: s2\n",
            "        target: renamed\n",
            "networks:\n",
            "  default:\n",
            "    name: gaps_default\n",
            "secrets:\n",
            "  s1:\n",
            "    name: gaps_s1\n",
            "    file: ./a.txt\n",
            "  s2:\n",
            "    name: gaps_s2\n",
            "    file: ./a.txt\n",
        )
    );
    assert_eq!(
        stack(source),
        concat!(
            "version: \"3.9\"\n",
            "services:\n",
            "  a:\n",
            "    image: busybox\n",
            "    secrets:\n",
            "      - source: s1\n",
            "      - source: s2\n",
            "        target: renamed\n",
            "secrets:\n",
            "  s1:\n",
            "    file: ./a.txt\n",
            "  s2:\n",
            "    file: ./a.txt\n",
        )
    );
}

/// A config or secret reference keeps the order the document wrote, and a repeat
/// collapses to the first position.
///
/// Measured on 29.8, `configs: [zz, aa, mm]`:
///
/// ```text
///     configs:
///       - source: zz
///       - source: aa
///       - source: mm
/// ```
///
/// The loader used to `sort()` the list, which put `mm` before `zz` in the
/// rendering. Order is part of the output a reader diffs.
#[test]
fn resource_references_keep_document_order() {
    let rendered = compose(concat!(
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    configs: [zz, aa, zz, mm]\n",
        "    secrets: [zz, aa]\n",
        "configs:\n",
        "  zz: {file: ./a.txt}\n",
        "  aa: {file: ./a.txt}\n",
        "  mm: {file: ./a.txt}\n",
        "secrets:\n",
        "  zz: {file: ./a.txt}\n",
        "  aa: {file: ./a.txt}\n",
    ));
    assert!(
        rendered.contains(concat!(
            "    configs:\n",
            "      - source: zz\n",
            "      - source: aa\n",
            "      - source: mm\n",
        )),
        "{rendered}"
    );
}

/// Gap 3 — `ulimits` keeps the spelling the document used.
///
/// Measured on 29.8:
///
/// ```text
///     ulimits:
///       nofile:
///         soft: 1024
///         hard: 2048
///       nproc: 65535
/// ```
///
/// The model normalized both to `{soft, hard}`, so `nproc: 65535` came back as a
/// mapping. This is the case where an `Option` on `soft`/`hard` would carry
/// nothing: the two spellings mean the same two numbers, and only the spelling
/// differs, so the model records it in `short_form`.
#[test]
fn a_ulimit_keeps_the_number_the_document_wrote() {
    let project = load(concat!(
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    ulimits:\n",
        "      nproc: 65535\n",
        "      nofile:\n",
        "        soft: 1024\n",
        "        hard: 2048\n",
    ));
    let limit = project
        .services
        .get("a")
        .expect("service a")
        .ulimits
        .iter()
        .find(|limit| limit.name == "nproc")
        .expect("the nproc limit");
    assert!(limit.short_form, "the bare number is recorded as itself");
    assert_eq!(
        limit.soft, 65535,
        "the number is still there for the Engine request"
    );
    assert!(
        ComposeConfigRenderer::render_yaml(&project).contains(concat!(
            "    ulimits:\n",
            "      nofile:\n",
            "        soft: 1024\n",
            "        hard: 2048\n",
            "      nproc: 65535\n",
        )),
        "{}",
        ComposeConfigRenderer::render_yaml(&project)
    );
}

/// A limit built by hand rather than parsed defaults to the long form, because
/// that is the only spelling that survives a round trip through the model.
#[test]
fn a_hand_built_limit_renders_as_the_long_form() {
    let mut project = load("name: gaps\nservices:\n  a:\n    image: busybox\n");
    project
        .services
        .get_mut("a")
        .expect("service a")
        .ulimits
        .push(ComposeUlimit {
            name: "nofile".to_owned(),
            soft: 1024,
            hard: 2048,
            short_form: false,
        });
    assert!(
        ComposeConfigRenderer::render_yaml(&project).contains(concat!(
            "    ulimits:\n",
            "      nofile:\n",
            "        soft: 1024\n",
            "        hard: 2048\n",
        )),
        "{}",
        ComposeConfigRenderer::render_yaml(&project)
    );
}

/// Gap 4 — `expose` keeps the spelling the document used.
///
/// Measured on 29.8, and the *quoting* is part of it:
///
/// ```text
///     expose:
///       - 3000-3005
///       - "9000"
///       - 80/udp
///       - "443"
///       - "80"
/// ```
///
/// `9000` is quoted because a bare `9000` would read back as a number, and
/// `80/udp` is not because it cannot. The loader used to append `/tcp` to a
/// protocol-less entry, which turned the first into `9000/tcp` — a key the
/// document never wrote, in a document whose whole purpose is to be re-loadable.
#[test]
fn expose_keeps_the_entry_the_document_wrote() {
    let rendered = compose(concat!(
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    expose:\n",
        "      - 3000-3005\n",
        "      - 9000\n",
        "      - 80/udp\n",
    ));
    assert!(
        rendered.contains(concat!(
            "    expose:\n",
            "      - 3000-3005\n",
            "      - \"9000\"\n",
            "      - 80/udp\n",
        )),
        "{rendered}"
    );
    assert!(
        !rendered.contains("/tcp"),
        "no protocol is invented for a protocol-less entry:\n{rendered}"
    );
}

/// Gap 5 — a mount prints the sub-mapping the document wrote, and the short
/// spelling gets the empty one Compose synthesizes.
///
/// Measured on 29.8, five spellings of the same two kinds:
///
/// ```text
///       - type: bind          # long form, no `bind:` key: nothing
///         source: /p
///         target: /d1
///       - type: bind          # long form that wrote an empty one
///         source: /p
///         target: /d2
///         bind: {}
///       - type: bind          # short form: the empty one Compose synthesizes
///         source: /p
///         target: /d3
///         bind: {}
///       - type: volume        # long form, no `volume:` key: nothing
///         source: vv
///         target: /d4
///       - type: tmpfs         # and the same for tmpfs
///         target: /d5
/// ```
///
/// The renderer used to print an empty sub-mapping unconditionally, which is
/// right for the short form and wrong for the first, second-to-last, and last of
/// the five. The sub-mapping's *contents* are real data Compose prints and this
/// model dropped, so they are carried now.
#[test]
fn a_mount_prints_the_sub_mapping_the_document_wrote() {
    let rendered = compose(concat!(
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    volumes:\n",
        "      - type: bind\n",
        "        source: /p\n",
        "        target: /d1\n",
        "      - type: bind\n",
        "        source: /p\n",
        "        target: /d2\n",
        "        bind: {}\n",
        "      - /p:/d3\n",
        "      - type: volume\n",
        "        source: vv\n",
        "        target: /d4\n",
        "      - type: volume\n",
        "        source: vv\n",
        "        target: /d5\n",
        "        volume: {}\n",
        "      - vv:/d6\n",
        "      - type: tmpfs\n",
        "        target: /d7\n",
        "      - type: tmpfs\n",
        "        target: /d8\n",
        "        tmpfs: {}\n",
        "volumes:\n",
        "  vv: {}\n",
    ));
    assert_eq!(
        rendered,
        concat!(
            "name: gaps\n",
            "services:\n",
            "  a:\n",
            "    image: busybox\n",
            "    networks:\n",
            "      default: null\n",
            "    volumes:\n",
            "      - type: bind\n",
            "        source: /p\n",
            "        target: /d1\n",
            "      - type: bind\n",
            "        source: /p\n",
            "        target: /d2\n",
            "        bind: {}\n",
            "      - type: bind\n",
            "        source: /p\n",
            "        target: /d3\n",
            "        bind: {}\n",
            "      - type: volume\n",
            "        source: vv\n",
            "        target: /d4\n",
            "      - type: volume\n",
            "        source: vv\n",
            "        target: /d5\n",
            "        volume: {}\n",
            "      - type: volume\n",
            "        source: vv\n",
            "        target: /d6\n",
            "        volume: {}\n",
            "      - type: tmpfs\n",
            "        target: /d7\n",
            "      - type: tmpfs\n",
            "        target: /d8\n",
            "        tmpfs: {}\n",
            "networks:\n",
            "  default:\n",
            "    name: gaps_default\n",
            "volumes:\n",
            "  vv:\n",
            "    name: gaps_vv\n",
        )
    );
}

/// v3 prints no sub-mapping for the short form. Measured on 29.8:
///
/// ```text
/// $ docker stack config
///     volumes:
///       - type: volume
///         source: nv
///         target: /data
/// ```
///
/// This is what `short_form` is for. A long form that wrote `bind: {}` keeps it
/// in both schemas, so the flag cannot be replaced by "is the sub-mapping empty".
#[test]
fn v3_drops_the_sub_mapping_the_short_form_synthesizes() {
    let rendered = stack(concat!(
        "version: \"3.9\"\n",
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    volumes:\n",
        "      - nv:/data\n",
        "      - type: bind\n",
        "        source: /p\n",
        "        target: /d2\n",
        "        bind: {}\n",
        "volumes:\n",
        "  nv: {}\n",
    ));
    assert_eq!(
        rendered,
        concat!(
            "version: \"3.9\"\n",
            "services:\n",
            "  a:\n",
            "    image: busybox\n",
            "    volumes:\n",
            "      - type: volume\n",
            "        source: nv\n",
            "        target: /data\n",
            "      - type: bind\n",
            "        source: /p\n",
            "        target: /d2\n",
            "        bind: {}\n",
            "volumes:\n",
            "  nv: {}\n",
        )
    );
}

/// The sub-mapping's members are carried, not dropped.
///
/// Measured on 29.8 against a document declaring every member, with `size: 10m`
/// and `mode: 0444` on the tmpfs:
///
/// ```text
///       - type: bind
///         bind:
///           selinux: Z
///           propagation: rshared
///       - type: volume
///         volume:
///           nocopy: true
///           subpath: inner
///       - type: tmpfs
///         tmpfs:
///           size: "1024"
///           mode: 292
/// ```
///
/// `size` prints as a quoted byte count because Compose's field is a string, and
/// `mode` prints as a number because Compose reads one — `mode: 0444` comes back
/// as `mode: 292`, and the quoted spelling is refused outright.
#[test]
fn a_sub_mapping_carries_its_members() {
    let project = load(concat!(
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    volumes:\n",
        "      - type: bind\n",
        "        source: /p\n",
        "        target: /d1\n",
        "        bind:\n",
        "          propagation: rshared\n",
        "          selinux: Z\n",
        "      - type: volume\n",
        "        source: vv\n",
        "        target: /d2\n",
        "        volume:\n",
        "          nocopy: true\n",
        "          subpath: inner\n",
        "      - type: tmpfs\n",
        "        target: /d3\n",
        "        tmpfs:\n",
        "          size: 10m\n",
        "          mode: 0444\n",
        "volumes:\n",
        "  vv: {}\n",
    ));
    let mount = |index: usize| project.services["a"].volumes[index].subtree.clone();
    assert_eq!(
        mount(0),
        Some(ComposeMountSubtree::Bind(
            neotales_docker_compose::ComposeBindOptions {
                propagation: Some("rshared".to_owned()),
                selinux: Some("Z".to_owned()),
            }
        ))
    );
    assert_eq!(
        mount(1),
        Some(ComposeMountSubtree::Volume(
            neotales_docker_compose::ComposeVolumeOptions {
                nocopy: Some(true),
                subpath: Some("inner".to_owned()),
            }
        ))
    );
    assert_eq!(
        mount(2),
        Some(ComposeMountSubtree::Tmpfs(
            neotales_docker_compose::ComposeTmpfsOptions {
                size: Some(10 * 1024 * 1024),
                mode: Some(0o444),
            }
        ))
    );
    let rendered = ComposeConfigRenderer::render_yaml(&project);
    assert!(
        rendered.contains(concat!(
            "        bind:\n",
            "          selinux: Z\n",
            "          propagation: rshared\n",
        )),
        "{rendered}"
    );
    assert!(
        rendered.contains(concat!(
            "        volume:\n",
            "          nocopy: true\n",
            "          subpath: inner\n",
        )),
        "{rendered}"
    );
    assert!(
        rendered.contains(concat!(
            "        tmpfs:\n",
            "          size: \"10485760\"\n",
            "          mode: 292\n",
        )),
        "{rendered}"
    );
}

/// A named volume's source is a key, not a path.
///
/// Measured on 29.8, over `- nv:/data` and `- ./rel:/d` with a project directory
/// of `/project`:
///
/// ```text
///       - type: volume
///         source: nv          # the key, unchanged
///         target: /data
///       - type: bind
///         source: /project/rel   # resolved, because it is a path
///         target: /d
/// ```
///
/// The renderer resolved both against the project directory, which produced
/// `/project/nv` — a path to nothing, for a volume that lives in the Engine's
/// volume store.
#[test]
fn a_named_volume_source_is_not_resolved_against_the_project_directory() {
    let rendered = compose_in(
        concat!(
            "name: gaps\n",
            "services:\n",
            "  a:\n",
            "    image: busybox\n",
            "    volumes:\n",
            "      - nv:/data\n",
            "      - ./rel:/d\n",
            "      - type: volume\n",
            "        source: nv\n",
            "        target: /other\n",
            "volumes:\n",
            "  nv: {}\n",
        ),
        "/project",
    );
    assert_eq!(
        rendered,
        concat!(
            "name: gaps\n",
            "services:\n",
            "  a:\n",
            "    image: busybox\n",
            "    networks:\n",
            "      default: null\n",
            "    volumes:\n",
            "      - type: volume\n",
            "        source: nv\n",
            "        target: /data\n",
            "        volume: {}\n",
            "      - type: bind\n",
            "        source: /project/rel\n",
            "        target: /d\n",
            "        bind: {}\n",
            "      - type: volume\n",
            "        source: nv\n",
            "        target: /other\n",
            "networks:\n",
            "  default:\n",
            "    name: gaps_default\n",
            "volumes:\n",
            "  nv:\n",
            "    name: gaps_nv\n",
        )
    );
}

/// A mount with no source prints no `source` key at all, not a null one.
///
/// Measured on 29.8, over `- type: tmpfs\n  target: /d` and `- /anon`:
///
/// ```text
///       - type: tmpfs
///         target: /d
///       - type: volume
///         target: /anon
///         volume: {}
/// ```
#[test]
fn a_sourceless_mount_prints_no_source_key() {
    let rendered = compose(concat!(
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    volumes:\n",
        "      - type: tmpfs\n",
        "        target: /d\n",
        "      - /anon\n",
    ));
    assert!(
        !rendered.contains("source: null"),
        "a null key is not the same as an absent one:\n{rendered}"
    );
    assert!(
        rendered.contains(concat!(
            "      - type: tmpfs\n",
            "        target: /d\n",
            "      - type: volume\n",
            "        target: /anon\n",
            "        volume: {}\n",
        )),
        "{rendered}"
    );
}

/// Gap 8 — a top-level resource no service refers to is pruned, but only by the
/// Compose schema.
///
/// Measured on 29.8, one service using `used` and one `unused` in each block:
///
/// ```text
/// $ docker compose config | grep -c unused   # 0
/// $ docker stack config  | grep -c unused    # 4
/// ```
///
/// The two commands disagree, so this cannot be a loading decision — the model
/// has to keep the whole document, and the pruning belongs to the rendering that
/// has to match. `external: true` does not save a resource from it either,
/// measured: a document whose only service referenced nothing rendered as `name`,
/// `services`, and `networks` and nothing else.
#[test]
fn an_unreferenced_top_level_resource_is_pruned_by_the_spec_only() {
    let source = concat!(
        "version: \"3.9\"\n",
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    networks: [used]\n",
        "    volumes: [used:/u]\n",
        "    configs: [used]\n",
        "    secrets: [used]\n",
        "networks:\n",
        "  used: {}\n",
        "  unused: {}\n",
        "volumes:\n",
        "  used: {}\n",
        "  unused: {}\n",
        "configs:\n",
        "  used: {file: ./a.txt}\n",
        "  unused: {file: ./a.txt}\n",
        "secrets:\n",
        "  used: {file: ./a.txt}\n",
        "  unused: {file: ./a.txt}\n",
    );
    let spec = compose(source);
    assert!(!spec.contains("unused"), "the spec prunes it:\n{spec}");
    let v3 = stack(source);
    assert_eq!(v3.matches("unused").count(), 4, "v3 keeps all four:\n{v3}");
}

/// An unreferenced resource the document marked `external: true` is pruned too,
/// and a document with no surviving service declares no implicit network at all.
///
/// Measured on 29.8, a document whose only service sits behind an inactive
/// profile rendered as exactly:
///
/// ```text
/// name: p3
/// services: {}
/// ```
///
/// and one declaring `networks: {default: {driver: bridge}}` next to a service
/// attached to `other` printed `networks: {other: {driver: bridge}}` — the
/// declared `default` was pruned like any other unreferenced network rather than
/// resurrected as the implicit one.
#[test]
fn the_implicit_network_appears_only_when_a_service_is_attached_to_it() {
    assert_eq!(
        compose(concat!(
            "name: gaps\n",
            "services: {}\n",
            "volumes:\n",
            "  v: {}\n",
        )),
        "name: gaps\nservices: {}\n"
    );
    assert_eq!(
        compose(concat!(
            "name: gaps\n",
            "services:\n",
            "  a:\n",
            "    image: busybox\n",
            "networks:\n",
            "  default: {driver: bridge}\n",
            "  other: {driver: overlay}\n",
        )),
        concat!(
            "name: gaps\n",
            "services:\n",
            "  a:\n",
            "    image: busybox\n",
            "    networks:\n",
            "      default: null\n",
            "networks:\n",
            "  default:\n",
            "    name: gaps_default\n",
            "    driver: bridge\n",
        )
    );
}

/// Gap 7 — a value that looks like a credential is replaced, and that is a
/// deliberate policy rather than a parity gap.
///
/// `docker compose config` prints the value. Printing it here too would put a
/// token in a rendered document, a digest, a log line, and anything that stores
/// the output, which is the opposite of what a `<redacted>` is for. So the
/// divergence is kept, on purpose, and this test says so rather than leaving the
/// next reader to decide whether it is a bug.
#[test]
fn a_credential_shaped_environment_value_is_redacted_on_purpose() {
    let rendered = compose(concat!(
        "name: gaps\n",
        "services:\n",
        "  a:\n",
        "    image: busybox\n",
        "    environment:\n",
        "      API_TOKEN: super-secret-value\n",
        "      PLAIN: value\n",
    ));
    assert!(rendered.contains("API_TOKEN: <redacted>"), "{rendered}");
    assert!(!rendered.contains("super-secret-value"), "{rendered}");
    assert!(rendered.contains("PLAIN: value"), "{rendered}");
}
