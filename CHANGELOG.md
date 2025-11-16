# CHANGELOG

## [unreleased](https://github.com/mozillazg/ptcpdump/compare/v0.37.0...HEAD)

## [v0.37.0](https://github.com/mozillazg/ptcpdump/compare/v0.36.0...v0.37.0) - 2025-11-16

- chore(deps): update quay.io/ptcpdump/develop docker tag to v20251115 ([#365](https://github.com/mozillazg/ptcpdump/pull/365)) (c26062f)
- feat(stdout/tcp): default to relative tcp sequence numbers ([#354](https://github.com/mozillazg/ptcpdump/pull/354)) (595e6fa)
- chore(deps): update module github.com/opencontainers/selinux to v1.13.0 [security] ([#362](https://github.com/mozillazg/ptcpdump/pull/362)) (c6e0686)
- fix(deps): update module github.com/containerd/containerd to v1.7.29 [security] ([#361](https://github.com/mozillazg/ptcpdump/pull/361)) (4c0f9bd)
- chore(deps): update golang docker tag to v1.25.4 ([#363](https://github.com/mozillazg/ptcpdump/pull/363)) (7de49d3)
- chore(deps): update all github action dependencies ([#364](https://github.com/mozillazg/ptcpdump/pull/364)) (15a867e)
- chore(deps): update actions/upload-artifact action to v5 ([#360](https://github.com/mozillazg/ptcpdump/pull/360)) (26e79da)
- chore(deps): update actions/download-artifact action to v6 ([#359](https://github.com/mozillazg/ptcpdump/pull/359)) (d42d494)
- chore(deps): update quay.io/ptcpdump/develop docker tag to v20251002.140939 ([#352](https://github.com/mozillazg/ptcpdump/pull/352)) (85eea04)
- chore(deps): update dependency golang to v1.25.2 ([#357](https://github.com/mozillazg/ptcpdump/pull/357)) (61b0c69)
- chore(deps): update golang docker tag to v1.25.2 ([#355](https://github.com/mozillazg/ptcpdump/pull/355)) (36e9a5c)

## [v0.36.0](https://github.com/mozillazg/ptcpdump/compare/v0.35.1...v0.36.0) - 2025-10-03

- chore: prepare for v0.36.0 ([#351](https://github.com/mozillazg/ptcpdump/pull/351)) (324649d)
- fix(bpf): fix filter_ok label to avoid C23 warning ([#350](https://github.com/mozillazg/ptcpdump/pull/350)) (a58d906)
- chore(deps): update quay.io/ptcpdump/develop docker tag to v20251002 ([#349](https://github.com/mozillazg/ptcpdump/pull/349)) (e966242)
- feat: ✨ Set up Copilot instructions for repository ([#348](https://github.com/mozillazg/ptcpdump/pull/348)) (dd2d37d)
- chore(deps): update actions/setup-go action to v6 ([#346](https://github.com/mozillazg/ptcpdump/pull/346)) (0052a68)
- feat(docs): Add docs site ([#345](https://github.com/mozillazg/ptcpdump/pull/345)) (434451f)
- feat: add CHANGELOG.md ([#344](https://github.com/mozillazg/ptcpdump/pull/344)) (884f0f1)
- btf: allow tests to run without network access ([#343](https://github.com/mozillazg/ptcpdump/pull/343)) (c873bed)
- feat(capture): handle L3-only devices and add tun regression ([#342](https://github.com/mozillazg/ptcpdump/pull/342)) (8f4c363)
- chore: enable PIE in dynamic builds ([#341](https://github.com/mozillazg/ptcpdump/pull/341)) (172121c)
- feat: Add kernel version validation to prevent CO-RE errors on unsupported kernels ([#340](https://github.com/mozillazg/ptcpdump/pull/340)) (0f1c8d7)
- chore(deps): pin dependencies ([#333](https://github.com/mozillazg/ptcpdump/pull/333)) (a397915)
- chore(deps): update golang docker tag to v1.25.1 ([#331](https://github.com/mozillazg/ptcpdump/pull/331)) (f333cb0)
- chore(deps): update busybox:latest docker digest to d82f458 ([#322](https://github.com/mozillazg/ptcpdump/pull/322)) (2eccf30)
- fix(deps): update all go dependencies master ([#316](https://github.com/mozillazg/ptcpdump/pull/316)) (609d5f0)

## [v0.35.1](https://github.com/mozillazg/ptcpdump/compare/v0.35.0...v0.35.1) - 2025-09-07
- fix(bpf): Correctly parse IP headers with options ([#337](https://github.com/mozillazg/ptcpdump/pull/337)) (a7eefa8)
- chore(deps): update actions/checkout action to v5 ([#334](https://github.com/mozillazg/ptcpdump/pull/334)) (2b157b7)
- fix(deps): update module github.com/docker/docker to v28 [security] ([#332](https://github.com/mozillazg/ptcpdump/pull/332)) (792f5f7)
- chore(deps): update all github action dependencies ([#327](https://github.com/mozillazg/ptcpdump/pull/327)) (f586e4a)
- chore(deps): update actions/download-artifact action to v5 ([#328](https://github.com/mozillazg/ptcpdump/pull/328)) (b2221af)
- chore(deps): update quay.io/ptcpdump/develop docker tag to v20250809 ([#329](https://github.com/mozillazg/ptcpdump/pull/329)) (f67c856)
- chore(deps): update golang:1.24.6-bookworm docker digest to 2679c15 ([#325](https://github.com/mozillazg/ptcpdump/pull/325)) (a8cece8)
- chore(deps): update dependency golang to v1.24.6 ([#326](https://github.com/mozillazg/ptcpdump/pull/326)) (c3e5d48)
- chore(deps): update golang docker tag to v1.24.6 ([#324](https://github.com/mozillazg/ptcpdump/pull/324)) (20209fd)
- chore(config): migrate config .github/renovate.json5 ([#323](https://github.com/mozillazg/ptcpdump/pull/323)) (d460d99)
- chore(deps): update golang docker tag to v1.24.5 ([#318](https://github.com/mozillazg/ptcpdump/pull/318)) (d2e667a)
- chore(deps): update all github action dependencies ([#319](https://github.com/mozillazg/ptcpdump/pull/319)) (cb728ca)

## [v0.35.0](https://github.com/mozillazg/ptcpdump/compare/v0.34.0...v0.35.0) - 2025-07-05
- chore(deps): update all lvh-images main ([#308](https://github.com/mozillazg/ptcpdump/pull/308)) (cd50da3)
- chore(deps): update cilium/little-vm-helper action to v0.0.25 ([#310](https://github.com/mozillazg/ptcpdump/pull/310)) (27c2bbf)
- feat(output): Include TLS Client Hello and Server Hello in default output ([#315](https://github.com/mozillazg/ptcpdump/pull/315)) (5189c33)
- fix(deps): update all go dependencies master to v0.33.2 ([#309](https://github.com/mozillazg/ptcpdump/pull/309)) (981d5b7)
- chore(deps): update docker/setup-buildx-action action to v3.11.1 ([#311](https://github.com/mozillazg/ptcpdump/pull/311)) (4aa08fe)
- feat(output): Include HTTP information in default output ([#314](https://github.com/mozillazg/ptcpdump/pull/314)) (c0f2e39)
- feat(output): Include IP options in verbose output ([#313](https://github.com/mozillazg/ptcpdump/pull/313)) (b94ba09)
- fix(deps): update all go dependencies master (minor) ([#302](https://github.com/mozillazg/ptcpdump/pull/302)) (80dc922)
- feat(output): Include network namespace inode ID in interface name for cross-namespace interfaces ([#307](https://github.com/mozillazg/ptcpdump/pull/307)) (5239bdd)
- chore(deps): update all lvh-images main ([#295](https://github.com/mozillazg/ptcpdump/pull/295)) (410861d)
- chore(deps): update quay.io/ptcpdump/develop docker tag to v20250614 ([#305](https://github.com/mozillazg/ptcpdump/pull/305)) (3b7956d)
- fix(deps): update all go dependencies master ([#301](https://github.com/mozillazg/ptcpdump/pull/301)) (34cf806)
- chore(deps): update all github action dependencies ([#294](https://github.com/mozillazg/ptcpdump/pull/294)) (904d702)
- chore(deps): update busybox:latest docker digest to f85340b ([#298](https://github.com/mozillazg/ptcpdump/pull/298)) (60f87c7)
- chore(deps): update golang docker tag to v1.24.4 ([#290](https://github.com/mozillazg/ptcpdump/pull/290)) (70c7ec8)
- chore(deps): update dependency golang to v1.24.4 ([#300](https://github.com/mozillazg/ptcpdump/pull/300)) (9e14dc7)
- feat(backend): Add `socket-filter` backend ([#304](https://github.com/mozillazg/ptcpdump/pull/304)) (1758188)
- chore(config): migrate config .github/renovate.json5 ([#299](https://github.com/mozillazg/ptcpdump/pull/299)) (588b963)

## [v0.34.0](https://github.com/mozillazg/ptcpdump/compare/v0.33.2...v0.34.0) - 2025-05-18
- feat(context): Add `--disable-reverse-match` flag to control reverse match behavior ([#297](https://github.com/mozillazg/ptcpdump/pull/297)) (be4c3ca)
- feat(backend): Add `tp-btf` backend ([#296](https://github.com/mozillazg/ptcpdump/pull/296)) (070955a)
- chore(Makefile): Added options in the Makefile to compile to position independent executable ([#291](https://github.com/mozillazg/ptcpdump/pull/291)) (be859f6)
- fix(logging): ignore unknown event type errors ([#293](https://github.com/mozillazg/ptcpdump/pull/293)) (ef6c817)
- chore(bpf): Attach additional hooks to save socket cookie info ([#292](https://github.com/mozillazg/ptcpdump/pull/292)) (64bd9eb)
- chore(deps): update all lvh-images main ([#199](https://github.com/mozillazg/ptcpdump/pull/199)) (e1a8e6f)
- [skip ci] docs(development): Improve development documentation ([#289](https://github.com/mozillazg/ptcpdump/pull/289)) (df22691)
- chore(bpf): Ignore errors when attaching optional BPF hooks ([#288](https://github.com/mozillazg/ptcpdump/pull/288)) (0e19dea)
- fix(deps): update all go dependencies master (minor) ([#255](https://github.com/mozillazg/ptcpdump/pull/255)) (d83a633)
- README.md: Improve and clarify wording and improve Markdown syntax ([#287](https://github.com/mozillazg/ptcpdump/pull/287)) (3325191)
- docs(kernel): Add documentation on required kernel configurations ([#286](https://github.com/mozillazg/ptcpdump/pull/286)) (80ce921)
- chore(deps): update busybox:latest docker digest to 37f7b37 ([#274](https://github.com/mozillazg/ptcpdump/pull/274)) (29edd8d)
- chore(deps): update all github action dependencies ([#250](https://github.com/mozillazg/ptcpdump/pull/250)) (ed40669)
- chore(deps): update golang docker tag to v1.24.2 ([#247](https://github.com/mozillazg/ptcpdump/pull/247)) (28a08ed)
- fix(deps): update all go dependencies master ([#249](https://github.com/mozillazg/ptcpdump/pull/249)) (725fa74)
- feat(platform): Add experimental support for ARM32 architecture ([#285](https://github.com/mozillazg/ptcpdump/pull/285)) (0663f91)
- chore(deps): bump golang.org/x/net from 0.36.0 to 0.38.0 ([#278](https://github.com/mozillazg/ptcpdump/pull/278)) (062d03b)

## [v0.33.2](https://github.com/mozillazg/ptcpdump/compare/v0.33.1...v0.33.2) - 2025-04-13
- fix: revert GetBootTimeNs() to fix timestamp drift ([#277](https://github.com/mozillazg/ptcpdump/pull/277)) (9e9e80a)

## [v0.33.1](https://github.com/mozillazg/ptcpdump/compare/v0.33.0...v0.33.1) - 2025-04-11
- chore(deps): update quay.io/ptcpdump/develop docker tag to v20250411 ([#276](https://github.com/mozillazg/ptcpdump/pull/276)) (af82075)
- chore(deps): update dependency golang to v1.23.8 ([#267](https://github.com/mozillazg/ptcpdump/pull/267)) (3d97f49)
- chore(deps): update busybox:latest docker digest to a5d0ce4 ([#242](https://github.com/mozillazg/ptcpdump/pull/242)) (b71ed71)
- renovate: change schedule to weekly ([#273](https://github.com/mozillazg/ptcpdump/pull/273)) (e9c0905)
- chore(deps): update golang docker tag to v1.23.8 ([#272](https://github.com/mozillazg/ptcpdump/pull/272)) (3fb35d2)
- fix(cli): Correct handling of `-s 0` for snapshot length ([#270](https://github.com/mozillazg/ptcpdump/pull/270)) (b5720da)
- chore(bpf): Add `ptcpdump_` prefix to all BPF programs and maps ([#269](https://github.com/mozillazg/ptcpdump/pull/269)) (53b192b)
- chore(test): Add more tests ([#265](https://github.com/mozillazg/ptcpdump/pull/265)) (bbcec2a)
- fix(deps): update module github.com/containerd/containerd to v1.7.27 [security] ([#263](https://github.com/mozillazg/ptcpdump/pull/263)) (236f288)

## [v0.33.0](https://github.com/mozillazg/ptcpdump/compare/v0.32.1...v0.33.0) - 2025-03-15
- chore: support dynamically link against libpcap ([#260](https://github.com/mozillazg/ptcpdump/pull/260)) (930193a)
- feat(cli): Add -tt, -ttt, -tttt, -ttttt flags for customizable timestamp formatting ([#262](https://github.com/mozillazg/ptcpdump/pull/262)) (a871ce9)
- feat(cli): Add `-F/--expression-file` flag to specify filter expression from file ([#261](https://github.com/mozillazg/ptcpdump/pull/261)) (af2a924)
- chore(deps): update module golang.org/x/net to v0.36.0 [security] ([#259](https://github.com/mozillazg/ptcpdump/pull/259)) (ebb8e3d)
- chore(deps): update golang docker tag to v1.23.7 ([#257](https://github.com/mozillazg/ptcpdump/pull/257)) (ebf1d74)
- feat(output): Add `-C` and `-W` flags for output file rotation based on size and count ([#251](https://github.com/mozillazg/ptcpdump/pull/251)) (764f1bb)
- feat(cli): add support for reading pcapng data from stdin using `-r -` ([#253](https://github.com/mozillazg/ptcpdump/pull/253)) (64f69d2)
- chore(ci): Add code coverage reporting to CI pipeline ([#252](https://github.com/mozillazg/ptcpdump/pull/252)) (a24d734)
- chore(ci): add arm64-test-backend, add test for release-test job ([#248](https://github.com/mozillazg/ptcpdump/pull/248)) (8342c51)

## [v0.32.1](https://github.com/mozillazg/ptcpdump/compare/v0.32.0...v0.32.1) - 2025-02-09
- fix(backend): enable process filtering for the `cgroup-skb` backend ([#246](https://github.com/mozillazg/ptcpdump/pull/246)) (792bbe1)
- chore(bpf): improve detection of backported tcx/ringbuf support in older kernels ([#244](https://github.com/mozillazg/ptcpdump/pull/244)) (020852d)
- chore(ci): fix Docker image build issues ([#245](https://github.com/mozillazg/ptcpdump/pull/245)) (d8b42a1)
- chore(deps): update cilium/little-vm-helper action to v0.0.23 ([#238](https://github.com/mozillazg/ptcpdump/pull/238)) (4d15144)
- fix(deps): update all go dependencies master (minor) ([#200](https://github.com/mozillazg/ptcpdump/pull/200)) (d946384)
- chore(deps): update busybox:latest docker digest to db142d4 ([#190](https://github.com/mozillazg/ptcpdump/pull/190)) (cc32a50)
- chore(deps): update all go dependencies master ([#239](https://github.com/mozillazg/ptcpdump/pull/239)) (f2371ce)
- chore(deps): update all github action dependencies ([#237](https://github.com/mozillazg/ptcpdump/pull/237)) (58cddda)
- chore(deps): update golang to 1.23.6 ([#241](https://github.com/mozillazg/ptcpdump/pull/241)) (44af488)
- chore(bpf): Use BPF ringbuf instead of perfbuf when kernel support is available ([#234](https://github.com/mozillazg/ptcpdump/pull/234)) (666f101)

## [v0.32.0](https://github.com/mozillazg/ptcpdump/compare/v0.31.0...v0.32.0) - 2025-01-19
- feat(filter): Add support for capturing traffic based on user ID ([#233](https://github.com/mozillazg/ptcpdump/pull/233)) (f5c4d69)
- chore(deps): update github.com/cilium/ebpf to v0.17.1 ([#232](https://github.com/mozillazg/ptcpdump/pull/232)) (924c6fa)
- chore(output): Remove group ID from output ([#231](https://github.com/mozillazg/ptcpdump/pull/231)) (3f1dab8)
- feat(capture): Enrich capture output with user information ([#230](https://github.com/mozillazg/ptcpdump/pull/230)) (3f9ca04)
- chore(build): Add --disable-rdma flag to libpcap build configuration ([#225](https://github.com/mozillazg/ptcpdump/pull/225)) (c2bdce9)
- docs(docker): Improve Docker usage documentation ([#226](https://github.com/mozillazg/ptcpdump/pull/226)) (4884ace)
- feat(backend/cgroup-skb): support for displaying thread ID and name in cgroup-skb output ([#215](https://github.com/mozillazg/ptcpdump/pull/215)) (e0bf4be)
- chore(deps): update golang:1.23-bookworm docker digest to 37a5567 ([#205](https://github.com/mozillazg/ptcpdump/pull/205)) (d8ecae9)
- fix(deps): update module github.com/x-way/pktdump to v0.0.6 ([#220](https://github.com/mozillazg/ptcpdump/pull/220)) (533689d)
- fix(deps): update module github.com/docker/docker to v27 ([#221](https://github.com/mozillazg/ptcpdump/pull/221)) (1f5fbf5)
- chore(deps): update all github action dependencies ([#219](https://github.com/mozillazg/ptcpdump/pull/219)) (77e654e)
- fix(deps): update module github.com/jschwinger233/elibpcap to v1 ([#222](https://github.com/mozillazg/ptcpdump/pull/222)) (6e1d3be)
- fix(deps): update all go dependencies master ([#201](https://github.com/mozillazg/ptcpdump/pull/201)) (12b20c0)

## [v0.31.0](https://github.com/mozillazg/ptcpdump/compare/v0.30.0...v0.31.0) - 2024-12-21
- feat: support filter by container-id prefix matching 12 or more characters ([#218](https://github.com/mozillazg/ptcpdump/pull/218)) (b4870fe)
- feat(platform): Add support for OpenWrt 24.10 on x86-64 architecture ([#214](https://github.com/mozillazg/ptcpdump/pull/214)) (e3fa2ee)
- chore(deps): update golang.org/x/net to v0.33.0 ([#212](https://github.com/mozillazg/ptcpdump/pull/212)) (a353f78)

## [v0.30.0](https://github.com/mozillazg/ptcpdump/compare/v0.29.0...v0.30.0) - 2024-12-08
- chore(bpf): Optimize BPF attachment by skipping netdev hooks when not using TC backend ([#209](https://github.com/mozillazg/ptcpdump/pull/209)) (7d71bb8)
- feat(capture): Add `--backend=cgroup-skb` support for cgroup-based packet capture ([#208](https://github.com/mozillazg/ptcpdump/pull/208)) (0308649)
- refactor(bpf): Restructure BPF code ([#207](https://github.com/mozillazg/ptcpdump/pull/207)) (1d3d114)
- feat(cli): Add `--backend` flag to specify packet capture backend ([#206](https://github.com/mozillazg/ptcpdump/pull/206)) (7bd3525)
- fix(bpf): Revert "optimize(bpf): Skip attaching {tcp,udp}_send* hooks when cgroup hooks are attached" ([#204](https://github.com/mozillazg/ptcpdump/pull/204)) (9e95911)
- chore(bpf): move nat related codes into nat.h ([#203](https://github.com/mozillazg/ptcpdump/pull/203)) (9476d37)

## [v0.29.0](https://github.com/mozillazg/ptcpdump/compare/v0.28.0...v0.29.0) - 2024-12-01
- optimize(bpf): Avoid storing short cgroup names in kernel space ([#198](https://github.com/mozillazg/ptcpdump/pull/198)) (529b2ff)
- optimize(bpf): Skip attaching {tcp,udp}_send* hooks when cgroup hooks are attached ([#197](https://github.com/mozillazg/ptcpdump/pull/197)) (1277cdb)
- chore(deps): update quay.io/ptcpdump/develop:latest docker digest to 5036b16 ([#196](https://github.com/mozillazg/ptcpdump/pull/196)) (64ad6b3)
- fix(deps): update all go dependencies master ([#158](https://github.com/mozillazg/ptcpdump/pull/158)) (84f0a6e)
- chore(config): migrate renovate config ([#195](https://github.com/mozillazg/ptcpdump/pull/195)) (1c2b98d)
- chore(deps): update docker/build-push-action action to v6 ([#192](https://github.com/mozillazg/ptcpdump/pull/192)) (bd671fd)
- chore(deps): update all github action dependencies ([#191](https://github.com/mozillazg/ptcpdump/pull/191)) (4c26673)
- chore(deps): pin golang docker tag to 3f3b9da ([#194](https://github.com/mozillazg/ptcpdump/pull/194)) (441ae2e)
- chore(config): migrate renovate config ([#193](https://github.com/mozillazg/ptcpdump/pull/193)) (4e94b85)
- chore(deps): update busybox:latest docker digest to 5b0f33c ([#188](https://github.com/mozillazg/ptcpdump/pull/188)) (2700cfa)

## [v0.28.0](https://github.com/mozillazg/ptcpdump/compare/v0.27.0...v0.28.0) - 2024-11-17
- chore(bpf): Use TCX where kernel support allows ([#187](https://github.com/mozillazg/ptcpdump/pull/187)) (0ef1419)
- chore(bpf): Improve compatibility with older kernels ([#186](https://github.com/mozillazg/ptcpdump/pull/186)) (a4ca7e9)
- feat(output): Add --context flag to specify context information in output ([#185](https://github.com/mozillazg/ptcpdump/pull/185)) (6f689b8)
- chore(bpf): Use BTF-powered raw tracepoint where kernel support allows ([#183](https://github.com/mozillazg/ptcpdump/pull/183)) (0190250)
- chore(bpf): Use fentry probes where kernel support allows ([#182](https://github.com/mozillazg/ptcpdump/pull/182)) (043e6b5)
- fix(tests): fix intermittent test failures ([#181](https://github.com/mozillazg/ptcpdump/pull/181)) (3c6b73c)
- fix 'invalid reference format' (89aeb01)

## [v0.27.0](https://github.com/mozillazg/ptcpdump/compare/v0.26.0...v0.27.0) - 2024-11-03
- fix(output/stdout): fix -c flag being ignored when combined with -r ([#180](https://github.com/mozillazg/ptcpdump/pull/180)) (a5c7105)
- feat(output/stdout): Add -q/--quiet flag for quiet output ([#179](https://github.com/mozillazg/ptcpdump/pull/179)) (8f7728a)
- fix(tests): fix intermittent test failures ([#178](https://github.com/mozillazg/ptcpdump/pull/178)) (66de6f8)
- chore(ci): add `timeout-minutes` to all jobs ([#177](https://github.com/mozillazg/ptcpdump/pull/177)) (174b61e)
- chore(deps): update all go dependencies master (minor) ([#176](https://github.com/mozillazg/ptcpdump/pull/176)) (c0786ec)
- chore(deps): update all lvh-images main ([#157](https://github.com/mozillazg/ptcpdump/pull/157)) (81b6fbd)
- chore(deps): update all github action dependencies ([#175](https://github.com/mozillazg/ptcpdump/pull/175)) (f32afc1)

## [v0.26.0](https://github.com/mozillazg/ptcpdump/compare/v0.25.0...v0.26.0) - 2024-10-27
- chore(deps): pin dependencies ([#174](https://github.com/mozillazg/ptcpdump/pull/174)) (ad1b48d)
- feat(docker): support running with docker ([#172](https://github.com/mozillazg/ptcpdump/pull/172)) (cc7fcfc)
- fix(interface): Handle nonexistent interfaces gracefully ([#173](https://github.com/mozillazg/ptcpdump/pull/173)) (245b206)
- feat(pcapng): Write Inbound/Outbound flag into the pcapng file and support parse it from file ([#171](https://github.com/mozillazg/ptcpdump/pull/171)) (3290757)
- chore(ci/arm64): Add Ubuntu 24.04 e2e test on ARM64 architecture ([#169](https://github.com/mozillazg/ptcpdump/pull/169)) (86ded2a)
- chore(deps): upgrade deps to fix CVEs ([#168](https://github.com/mozillazg/ptcpdump/pull/168)) (1ef0057)

## [v0.25.0](https://github.com/mozillazg/ptcpdump/compare/v0.24.0...v0.25.0) - 2024-10-19
- feat(pcapng): Read interface name from pcapng file and optimize interface handling when writing ([#165](https://github.com/mozillazg/ptcpdump/pull/165)) (119581c)
- fix(capture/subprogram): Fix capture by process via run target program ([#166](https://github.com/mozillazg/ptcpdump/pull/166)) (2cb31ff)
- feat(capture): Automatically capture traffic from/to new interfaces when using `-i any`, `--netns any` or `--netns newly` (c3a5bca)
- feat(capture): Add `--netns` flag to capture traffic from/to interfaces in other network namespaces ([#160](https://github.com/mozillazg/ptcpdump/pull/160)) (cdd4253)

## [v0.24.0](https://github.com/mozillazg/ptcpdump/compare/v0.23.0...v0.24.0) - 2024-10-04
- feat(output/tcp): support SACK and TFO ([#159](https://github.com/mozillazg/ptcpdump/pull/159)) (52782fc)
- feat(output): display MPTCP options ([#152](https://github.com/mozillazg/ptcpdump/pull/152)) (c6fbd56)
- feat(experimental/gotls): support environment variable `SSLKEYLOGFILE` ([#151](https://github.com/mozillazg/ptcpdump/pull/151)) (00198b9)
- feat(output): display TCP options by default ([#150](https://github.com/mozillazg/ptcpdump/pull/150)) (637d04a)

## [v0.23.0](https://github.com/mozillazg/ptcpdump/compare/v0.22.0...v0.23.0) - 2024-09-22
- feat(experimental/gotls): support stripped and/or PIE enabled binary ([#147](https://github.com/mozillazg/ptcpdump/pull/147)) (c9099fb)
- fix(experimental/gotls): fix label of tls key log sometimes is empty ([#146](https://github.com/mozillazg/ptcpdump/pull/146)) (bdb5f10)
- feat(experimental): Add `--embed-keylog-to-pcapng` flag for embeding TLS key logs into pcapng file ([#144](https://github.com/mozillazg/ptcpdump/pull/144)) (00b9018)
- feat(experimental): Add `--write-keylog-file` flag for saving TLS key logs ([#143](https://github.com/mozillazg/ptcpdump/pull/143)) (90b4319)

## [v0.22.0](https://github.com/mozillazg/ptcpdump/compare/v0.21.0...v0.22.0) - 2024-09-13
- chore(deps): update all lvh-images main ([#125](https://github.com/mozillazg/ptcpdump/pull/125)) (aaa6ea4)
- chore(deps): update all go dependencies master ([#123](https://github.com/mozillazg/ptcpdump/pull/123)) (a487ecc)
- chore(deps): pin dependencies ([#124](https://github.com/mozillazg/ptcpdump/pull/124)) (cf1afcd)
- chore(deps): bump libpcap from 1.10.4 to 1.10.5 ([#130](https://github.com/mozillazg/ptcpdump/pull/130)) (08c400d)
- chore(renovate): Ignore additional dependencies in renovate config ([#129](https://github.com/mozillazg/ptcpdump/pull/129)) (0747113)
- chore(develop): Add Docker image for development environment ([#128](https://github.com/mozillazg/ptcpdump/pull/128)) (b43d192)
- chore(deps): bump github.com/opencontainers/runc from 1.1.12 to 1.1.14 ([#127](https://github.com/mozillazg/ptcpdump/pull/127)) (c7249d4)
- chore(deps): update module github.com/shirou/gopsutil/v3 to v4 ([#120](https://github.com/mozillazg/ptcpdump/pull/120)) (82990c7)

## [v0.21.0](https://github.com/mozillazg/ptcpdump/compare/v0.20.0...v0.21.0) - 2024-08-25
- docs: Update examples, development instructions, and add Chinese README ([#119](https://github.com/mozillazg/ptcpdump/pull/119)) (2676a2e)
- feat(user): Add `-A` flag for printing packet data in ASCII ([#118](https://github.com/mozillazg/ptcpdump/pull/118)) (403b601)
- feat(user): Add `-x`, `-xx`, `-X`, and `-XX` flags for packet data display in hex and/or ASCII ([#117](https://github.com/mozillazg/ptcpdump/pull/117)) (feb5b06)
- chore(deps): update all lvh-images main ([#103](https://github.com/mozillazg/ptcpdump/pull/103)) (f0cee18)
- feat(user): Add `--micro`, `--nano`, and `--time-stamp-precision` flags for time stamp precision control ([#116](https://github.com/mozillazg/ptcpdump/pull/116)) (68f8d2e)
- feat(user): Add support for filtering traffic by multiple PIDs via --pid flag ([#115](https://github.com/mozillazg/ptcpdump/pull/115)) (b4685a5)

## [v0.20.0](https://github.com/mozillazg/ptcpdump/compare/v0.19.0...v0.20.0) - 2024-08-17
- tc: no longer overwrite filter and replace qdisc ([#114](https://github.com/mozillazg/ptcpdump/pull/114)) (01f0890)
- chore(deps): update all go dependencies master ([#102](https://github.com/mozillazg/ptcpdump/pull/102)) (7759601)
- bpf: return TC_ACT_UNSPEC instead of TC_ACT_OK to trigger other classifiers ([#113](https://github.com/mozillazg/ptcpdump/pull/113)) (fa0274b)
- chore: use github.com/smira/go-xz instead of github.com/mholt/archiver ([#112](https://github.com/mozillazg/ptcpdump/pull/112)) (74d0f7e)

## [v0.19.0](https://github.com/mozillazg/ptcpdump/compare/v0.18.0...v0.19.0) - 2024-08-10
- fix can not filter by pod that contains multiple containers ([#111](https://github.com/mozillazg/ptcpdump/pull/111)) (aa5159e)
- terminate program with error if filtered pod/container is not running ([#110](https://github.com/mozillazg/ptcpdump/pull/110)) (fcb6508)
- Add vendor ([#109](https://github.com/mozillazg/ptcpdump/pull/109)) (b62f829)
- fix can't filter by pod name include dot ([#108](https://github.com/mozillazg/ptcpdump/pull/108)) (9d7ada7)

## [v0.18.0](https://github.com/mozillazg/ptcpdump/compare/v0.17.0...v0.18.0) - 2024-08-10
- fix filter by process/container/pod not working on Dockershim based environment ([#106](https://github.com/mozillazg/ptcpdump/pull/106)) (f505c95)
- chore(deps): update module github.com/docker/distribution to v2.8.2+incompatible [security] ([#100](https://github.com/mozillazg/ptcpdump/pull/100)) (dd54b8d)
- chore(deps): update module github.com/opencontainers/runc to v1.1.12 [security] ([#101](https://github.com/mozillazg/ptcpdump/pull/101)) (68fdf94)
- kubernetes: support CRI v1 and v1alpha2 at the same time ([#99](https://github.com/mozillazg/ptcpdump/pull/99)) (f09f517)
- add parent process info into the context and comments ([#97](https://github.com/mozillazg/ptcpdump/pull/97)) (f89a638)
- skip interface which cause "netlink receive: no such file or directory" ([#98](https://github.com/mozillazg/ptcpdump/pull/98)) (ebd7525)
- chore(deps): update cilium/little-vm-helper action to v0.0.19 ([#95](https://github.com/mozillazg/ptcpdump/pull/95)) (283e35c)
- chore(deps): update all lvh-images main ([#94](https://github.com/mozillazg/ptcpdump/pull/94)) (02b3f20)
- chore(deps): update all github action dependencies ([#93](https://github.com/mozillazg/ptcpdump/pull/93)) (f8a2ac3)
- Add issue templates ([#92](https://github.com/mozillazg/ptcpdump/pull/92)) (0841055)

## [v0.17.0](https://github.com/mozillazg/ptcpdump/compare/v0.16.0...v0.17.0) - 2024-07-20
- improve compatibility with OpenCloudOS 7/8/9 and TencentOS Server 2.4/3.1 ([#91](https://github.com/mozillazg/ptcpdump/pull/91)) (1fb0f66)
- Improve compatible with old kernel ([#88](https://github.com/mozillazg/ptcpdump/pull/88)) (9a639ef)
- fix(deps): update all go dependencies master ([#49](https://github.com/mozillazg/ptcpdump/pull/49)) (52816bf)
- fix(deps): update all go dependencies master ([#84](https://github.com/mozillazg/ptcpdump/pull/84)) (966d308)

## [v0.16.0](https://github.com/mozillazg/ptcpdump/compare/v0.15.0...v0.16.0) - 2024-07-06
- chore(deps): update goreleaser/goreleaser-action action to v6 ([#85](https://github.com/mozillazg/ptcpdump/pull/85)) (dec79a7)
- chore(deps): update all lvh-images main ([#81](https://github.com/mozillazg/ptcpdump/pull/81)) (055e998)
- Support linux kernel version >= 4.19, < 5.2 ([#83](https://github.com/mozillazg/ptcpdump/pull/83)) (bcd9064)
- chore(deps): update actions/checkout digest to 692973e ([#82](https://github.com/mozillazg/ptcpdump/pull/82)) (1b50597)
- all: reduce dependencies ([#80](https://github.com/mozillazg/ptcpdump/pull/80)) (2651527)

## [v0.15.0](https://github.com/mozillazg/ptcpdump/compare/v0.14.0...v0.15.0) - 2024-06-29
- Remove dead processes from the process cache through handle exit events ([#79](https://github.com/mozillazg/ptcpdump/pull/79)) (76e94e8)
- Add new flag `-s/--snapshot-length SNAPLEN` ([#78](https://github.com/mozillazg/ptcpdump/pull/78)) (54f0ecc)
- Support filter by pod via `--pod-name NAME.NAMESPACE` ([#75](https://github.com/mozillazg/ptcpdump/pull/75)) (e41a973)

## [v0.14.0](https://github.com/mozillazg/ptcpdump/compare/v0.13.0...v0.14.0) - 2024-06-16
- Add new flag `--docker-address`, `--containerd-address`, `--cri-runtime-address` ([#74](https://github.com/mozillazg/ptcpdump/pull/74)) (f844a9e)
- Add new flag `--log-level` ([#73](https://github.com/mozillazg/ptcpdump/pull/73)) (c7f09bd)

## [v0.13.0](https://github.com/mozillazg/ptcpdump/compare/v0.12.0...v0.13.0) - 2024-06-16
- Print less process information by default ([#72](https://github.com/mozillazg/ptcpdump/pull/72)) (9f8d4b7)
- Support filter by container name via `--container-name CONTAINER-NAME` ([#71](https://github.com/mozillazg/ptcpdump/pull/71)) (8bd471a)
- Support filter by container id via `--container-id CONTAINER-ID` ([#70](https://github.com/mozillazg/ptcpdump/pull/70)) (745a95c)
- chore(deps): update all lvh-images main ([#69](https://github.com/mozillazg/ptcpdump/pull/69)) (608d0cd)

## [v0.12.0](https://github.com/mozillazg/ptcpdump/compare/v0.11.0...v0.12.0) - 2024-06-15
- Add new flag `-v` to produce verbose output, print less info without `-v` ([#67](https://github.com/mozillazg/ptcpdump/pull/67)) (9ef1e72)
- renovate: avoid unexpected major/minor update of kernel images ([#68](https://github.com/mozillazg/ptcpdump/pull/68)) (4a0f628)
- renovate: fix update kernel images ([#66](https://github.com/mozillazg/ptcpdump/pull/66)) (9a64222)
- renovate: add rule to match version of kernel-images ([#64](https://github.com/mozillazg/ptcpdump/pull/64)) (1d0261f)
- renovate: support check version of kernel-images ([#63](https://github.com/mozillazg/ptcpdump/pull/63)) (c832e3d)
- improve associate context for exist connections ([#62](https://github.com/mozillazg/ptcpdump/pull/62)) (2b5b1c5)

## [v0.11.0](https://github.com/mozillazg/ptcpdump/compare/v0.10.0...v0.11.0) - 2024-06-11
- support add kubernetes pod context into the packet comments ([#59](https://github.com/mozillazg/ptcpdump/pull/59)) (1f808db)
- add new flag: `-n` ([#55](https://github.com/mozillazg/ptcpdump/pull/55)) (913dfa1)
- add new flag `-D`: Print the list of the network interfaces available on the system ([#53](https://github.com/mozillazg/ptcpdump/pull/53)) (1bc5d1d)
- add new flag `--count`: Print only on stdout the packet count when reading capture file instead of parsing/printing the packets ([#52](https://github.com/mozillazg/ptcpdump/pull/52)) (4cf7116)

## [v0.10.0](https://github.com/mozillazg/ptcpdump/compare/v0.9.0...v0.10.0) - 2024-06-09
- container-aware: support containerd ([#51](https://github.com/mozillazg/ptcpdump/pull/51)) (8de9459)
- Container aware: add container context as packet comments ([#50](https://github.com/mozillazg/ptcpdump/pull/50)) (b6d1b05)
- Add new flag `-#, --number`: Print an optional packet number at the beginning of the line ([#48](https://github.com/mozillazg/ptcpdump/pull/48)) (e5d120c)
- Add new flag `-t`: Don't print a timestamp on each dump line ([#47](https://github.com/mozillazg/ptcpdump/pull/47)) (048292b)

## [v0.9.0](https://github.com/mozillazg/ptcpdump/compare/v0.8.0...v0.9.0) - 2024-05-29
- chore(deps): update all github action dependencies ([#26](https://github.com/mozillazg/ptcpdump/pull/26)) (d0d38c9)
- chore(deps): update cilium/little-vm-helper action to v0.0.18 ([#5](https://github.com/mozillazg/ptcpdump/pull/5)) (3409996)
- support add process info for the packets were translated by NAT ([#46](https://github.com/mozillazg/ptcpdump/pull/46)) (c2efdf2)
- chore: code format and cleanup ([#45](https://github.com/mozillazg/ptcpdump/pull/45)) (fa60274)
- Add new flag `--oneline` to support print parsed packet output in a single line ([#44](https://github.com/mozillazg/ptcpdump/pull/44)) (a642238)

## [v0.8.0](https://github.com/mozillazg/ptcpdump/compare/v0.7.0...v0.8.0) - 2024-05-24
- support arm64 ([#41](https://github.com/mozillazg/ptcpdump/pull/41)) (1912001)
- docs: add example for support multiple interfaces ([#39](https://github.com/mozillazg/ptcpdump/pull/39)) (60a7925)
- Create CODE_OF_CONDUCT.md ([#38](https://github.com/mozillazg/ptcpdump/pull/38)) (361f246)

## [v0.7.0](https://github.com/mozillazg/ptcpdump/compare/v0.6.0...v0.7.0) - 2024-05-18
- support write to standard output ([#37](https://github.com/mozillazg/ptcpdump/pull/37)) (84226e7)
- report counts when finished capturing packets or receive SIGUSR1 signal ([#36](https://github.com/mozillazg/ptcpdump/pull/36)) (40a26b8)

## [v0.6.0](https://github.com/mozillazg/ptcpdump/compare/v0.5.2...v0.6.0) - 2024-05-17
- support capture packets of short-lived program via run target program by ptcpdump ([#33](https://github.com/mozillazg/ptcpdump/pull/33)) (bd7fc41)
- Support associate process info for any protocol when possible ([#32](https://github.com/mozillazg/ptcpdump/pull/32)) (3f06f23)
- renovate: fix config ([#31](https://github.com/mozillazg/ptcpdump/pull/31)) (57425f3)
- renovate: change schedule to monthly ([#29](https://github.com/mozillazg/ptcpdump/pull/29)) (233df25)
- chore: rename make generate to make build-bpf ([#28](https://github.com/mozillazg/ptcpdump/pull/28)) (463e011)

## [v0.5.2](https://github.com/mozillazg/ptcpdump/compare/v0.5.1...v0.5.2) - 2024-05-10
- Fix unable to associate process information for packets sent from connections that exist before ptcpdump is started ([#27](https://github.com/mozillazg/ptcpdump/pull/27)) (d3d6664)

## [v0.5.1](https://github.com/mozillazg/ptcpdump/compare/v0.5.0...v0.5.1) - 2024-05-07
- bpf: avoid data reuse ([#20](https://github.com/mozillazg/ptcpdump/pull/20)) (e0e33dc)

## [v0.5.0](https://github.com/mozillazg/ptcpdump/compare/v0.4.0...v0.5.0) - 2024-05-07
- support write packets to pcap file ([#19](https://github.com/mozillazg/ptcpdump/pull/19)) (ac9732a)
- Capture all packets by default, even if process info cannot be associated ([#18](https://github.com/mozillazg/ptcpdump/pull/18)) (3771399)
- support read packets from pcap file ([#16](https://github.com/mozillazg/ptcpdump/pull/16)) (0c197ae)
- build(deps): bump golang.org/x/net from 0.21.0 to 0.23.0 ([#13](https://github.com/mozillazg/ptcpdump/pull/13)) (b25b6ec)

## [v0.4.0](https://github.com/mozillazg/ptcpdump/compare/v0.3.0...v0.4.0) - 2024-05-05
- test: increase worker number (85422e6)
- add --exec-events-worker-number to speed up handle exec events (abebcec)
- docs: improve table (9d6ba6d)
- add --event-chan-size and --delay-before-handle-packet-events for improve e2e test (4a68897)
- docs: add badge (23306f0)
- docs: compare with tcpdump (91867e1)
- chore(deps): pin cilium/little-vm-helper action to 908ab1f ([#12](https://github.com/mozillazg/ptcpdump/pull/12)) (ce08b51)
- fix(deps): update module golang.org/x/sys to v0.20.0 ([#11](https://github.com/mozillazg/ptcpdump/pull/11)) (f86d282)
- test: capture more packets when test (be59720)
- bpf: remove unused codes (bd9cc0d)
- Makefile: add e2e (e884cc4)
- add -r flag for reading packets from pcapng file (14f89ae)
- chore(deps): update actions/setup-go digest to cdcb360 ([#10](https://github.com/mozillazg/ptcpdump/pull/10)) (6ceb962)

## [v0.3.0](https://github.com/mozillazg/ptcpdump/compare/v0.2.1...v0.3.0) - 2024-05-03
- bpf: hook raw_tracepoint/sched_process_exit (60206cc)
- test: sleep 10s before run curl command (ba4ed8b)
- ci: fix host path (80b112b)
- bpf: use raw_tracepoint instead of tracepoint (37a01a3)
- bpf: use sched_process_fork instead of clone/clone3/fork/vfork (5a80d3a)
- fix(deps): update module github.com/cilium/ebpf to v0.15.0 ([#6](https://github.com/mozillazg/ptcpdump/pull/6)) (5ec5e91)
- fix(deps): update module github.com/shirou/gopsutil/v3 to v3.24.4 ([#7](https://github.com/mozillazg/ptcpdump/pull/7)) (c41985b)
- renovate: ignore fork packages (7ee12a5)
- chore(deps): pin dependencies ([#4](https://github.com/mozillazg/ptcpdump/pull/4)) (385be85)

## [v0.2.1](https://github.com/mozillazg/ptcpdump/compare/v0.2.0...v0.2.1) - 2024-04-29
- renovate: fix branch name (37d7479)
- ci: add renovate (d0370dd)
- ci: add run e2e test on linux 5.4 (96d91b6)
- bufix: fix "Can't send statistics for non existent interface" (de8547d)
- fix docs (cca4c04)

## [v0.2.0](https://github.com/mozillazg/ptcpdump/compare/v0.1.0...v0.2.0) - 2024-04-28
- fill all interfaces when init pcapng writer (372a523)
- change to use perf_event for exec events (24080e1)
- add new flag: -Q/--direction (680f2d2)

## [v0.1.0](https://github.com/mozillazg/ptcpdump/compare/v0.1.0-dev.1...v0.1.0) - 2024-04-27
- ci: add e2e test (131905c)
- update docs (4aa7502)
- add new flag: -c (1437442)
- add new flag: --print (e750e34)
- update docs (2b93568)
- fix not apply pcap filters after migrate to use cobra (acd7280)

## [v0.1.0-dev.1](https://github.com/mozillazg/ptcpdump/compare/9b882a0...v0.1.0-dev.1) - 2024-04-27
- ci: add goreleaser (9159348)
- strip `v` when output version (eee278d)
- update version info when build (5601e18)
- ci: add actions (8d9e3f6)
- ci: add actions (e243343)
- add new flag --version and include os and version in the section options (8d9b458)
- -i support multiple interfaces (9606ba0)
- change to use spf13/cobra (43a7026)
- improve stdout format (98a1f87)
- add new flag: --list-interface (c70eac3)
- support filter with pcap-filter expression (5afac24)
- support filter packet send by child processes when filter by pid/comm (e3b2761)
- build with statically linking (ebaf492)
- include real packet time (dfdd22e)
- record real packet size (f9bbd57)
- support filter by process comm (d4511b3)
- support filter by pid (1f54448)
- add -i flag (f48a30d)
- support change saved file path (896c3fb)
- make stdout output format like tcpdump (ac0b2ac)
- support fill info of running processes (275ee3e)
- get filename from exec event (3e8bc18)
- hook exec events to get args of pid (59397c4)
- remove vendor (19537ef)
- chore: Reorganize the codes (a50287b)
- a working poc (440631f)
- Initial commit (9b882a0)
