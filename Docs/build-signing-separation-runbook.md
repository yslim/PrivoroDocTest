# Shiba 빌드/서명 분리 — 검증 절차서

개인키가 **전혀 없는** 빌드 머신에서 Yocto 이미지를 만들고, 소스도 sstate도 없는 **별도 서명 머신**에서 서명해 최종 산출물을 만드는 전 과정. 2026-08-27 두 대의 OrbStack VM으로 실제 수행하고 암호학적으로 검증한 기록이다.

| | 머신 | 역할 |
|---|---|---|
| 빌드 | `yocto-stm32` | Ubuntu 22.04 jammy / arm64 / 9코어 27GB — 개인키 없음 |
| 서명 | `yocto-signing` | **Debian 12 bookworm** / arm64 — 빌드 트리 없음, 키만 있음 |

배포판을 일부러 다르게 했다. 번들이 정말 자립적인지 확인하기 위해서다.

관련 브랜치: `build-signing-separation` (`meta-secure-boot`, base `mfa-integration`)

---

## 0. 개념

빌드는 `SHIBA_SIGN_MODE`로 제어한다.

| 모드 | 개인키 | TF-A `.stm32` | FIP | 커널 FIT | SWU |
|---|---|---|---|---|---|
| `full` (기본) | 필요 | 헤더 서명됨, `_Signed` | CoT 인증서 포함 | 서명됨 | CMS 서명 |
| `unsigned` | 불필요 | 헤더 서명필드 0 | CoT 인증서 없음 | signature 노드만, 값 비움 | `.sig` 없음 |

**두 모드의 바이너리 자체는 동일하다.** `unsigned`는 약한 제품을 만드는 게 아니라 TF-A의 `TRUSTED_BOARD_BOOT`/`MEASURED_BOOT`를 그대로 유지한 채 **개인키를 쓰는 네 단계만 남겨둔다.** 각 단계는 산출물만 가지고 나중에 완성할 수 있는 형태다.

> **`SIGN_ENABLE = 0` 을 쓰면 안 된다.** meta-st에서 이 스위치는 서명뿐 아니라 `TRUSTED_BOARD_BOOT`와 mbedtls, 그에 딸린 `MEASURED_BOOT`까지 끈다. 실측하면 BL2의 mbedtls 심볼이 4→0, measured-boot 문자열이 35→4가 된다. FIP 인증도 PCR 확장도 못 하는 바이너리가 나오고, 거기에 헤더만 서명하면 "서명은 됐지만 신뢰사슬이 없는" 디바이스가 된다.

---

## 1. 서명 머신 준비

```bash
orbctl create debian:bookworm yocto-signing
```

### 전제 패키지

```bash
sudo apt-get update && sudo apt-get install -y cpio
```

ST 도구는 x86-64 바이너리다. arm64 호스트에서는 멀티아키텍처 라이브러리가 필요하다.

```bash
sudo dpkg --add-architecture amd64
sudo apt-get update
sudo apt-get install -y libc6:amd64 libstdc++6:amd64 libglib2.0-0:amd64
```

`debugfs`, `mkimage`, `fiptool`, `cert_create`는 설치하지 않는다 — 번들이 자체 버전을 싣고 온다.

### STM32CubeProgrammer

`STM32MP_SigningTool_CLI`와 `STM32MP_KeyGen_CLI`가 필요하다. ST 라이선스 대상이라 번들에 포함되지 않는다.

```bash
mkdir -p ~/STMicroelectronics/STM32Cube
cp -a /mnt/machines/yocto-stm32/home/yslim/STMicroelectronics/STM32Cube/STM32CubeProgrammer ~/STMicroelectronics/STM32Cube/
```

동작 확인:

```bash
~/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32MP_SigningTool_CLI --version
```

---

## 2. 키 생성 (서명 머신에서만)

```bash
K=~/signing-keys
mkdir -p $K/swu-sign-3072 && cd $K
```

### 2.1 패스프레이즈

```bash
openssl rand -base64 24 | tr -d '\n=+/' | cut -c1-20 > pass
chmod 600 pass
```

### 2.2 ST Root of Trust 키 (ECDSA P-256)

```bash
~/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32MP_KeyGen_CLI \
    -pwd "$(cat pass)" -abs $K -n 1
mv privateKey00.pem privateKey.pem
mv publicKey00.pem publicKey.pem
mv publicKeyHash00.bin publicKeyhash.bin
rm -f publicKeysHashHashes.bin
chmod 600 privateKey.pem
```

> ⚠️ **`-ecc 1` 을 붙이면 안 된다.** 도움말은 "1. prime256v1 2. brainpoolP256t1 / `-ecc 1` <Default>" 라고 하지만, **실제로는 `-ecc 1`이 brainpoolP256t1을 만든다.** 생략해야 prime256v1(NIST P-256)이 나온다. 실측:
> ```
> -pwd … -abs …            -> prime256v1
> -pwd … -abs … -ecc 1     -> brainpoolP256t1
> -pwd … -abs … -n 1       -> prime256v1
> ```

### 2.3 FIT 서명 키

```bash
for n in uboot-sign-key uboot-sign-img-key; do
    openssl genpkey -algorithm RSA -out $n.key -pkeyopt rsa_keygen_bits:2048
    openssl req -batch -new -x509 -key $n.key -out $n.crt -days 3650 \
        -subj "/CN=Shiba FIT $n"
done
```

### 2.4 SWU CMS 서명 키

키 크기는 브랜치 정책(`SWU_SIGN_KEY_BITS`, 현재 3072)이다.

```bash
openssl genpkey -algorithm RSA -out swu-sign-3072/swu-sign-key.pem -pkeyopt rsa_keygen_bits:3072
openssl req -batch -new -x509 -key swu-sign-3072/swu-sign-key.pem \
    -out swu-sign-3072/swu-sign-cert.pem -days 3650 -subj "/CN=Shiba SWU Signing"
chmod 600 swu-sign-3072/swu-sign-key.pem
```

### 2.5 확인

```bash
openssl pkey -pubin -in publicKey.pem -noout -text | grep "NIST CURVE"   # P-256
xxd -p publicKeyhash.bin | tr -d '\n'                                    # OTP 퓨징 대상
```

---

## 3. 공개 재료만 빌드 머신으로

**개인키와 `pass`는 절대 나가지 않는다.**

```bash
P=/mnt/machines/yocto-stm32/home/yslim/pubkeys-new
mkdir -p $P/swu-sign-3072
cp ~/signing-keys/publicKey.pem $P/
cp ~/signing-keys/uboot-sign-key.crt ~/signing-keys/uboot-sign-img-key.crt $P/
cp ~/signing-keys/swu-sign-3072/swu-sign-cert.pem $P/swu-sign-3072/
chmod 644 $P/*.pem $P/*.crt $P/swu-sign-3072/*.pem
```

유출 검사:

```bash
grep -rl "PRIVATE KEY" $P ; test ! -e $P/pass && echo "pass 없음 OK"
```

| 파일 | 어디에 들어가나 |
|---|---|
| `publicKey.pem` | ST 서명 도구에 전달 (`publicKey*.pem` 글롭) |
| `uboot-sign-key.crt` | `u-boot-<dt>-default.dtb` → FIP 의 `HW_CONFIG` (U-Boot 의 런타임 control FDT) |
| `swu-sign-cert.pem` | **rootfs** (dm-verity 보호) |
| ROT 공개키 해시 | 디바이스 OTP 퓨즈 — 이미지에는 안 들어감 |

> `swu-sign-cert.pem`은 verity로 보호되는 rootfs 안에 들어가므로 **빌드 후에 교체할 수 없다.** 빌드 전에 확정해야 한다.

---

## 4. 빌드 머신: 워크스페이스

```bash
mkdir -p ~/yocto/unsigned-build && cd ~/yocto/unsigned-build

~/.bin/repo init -u git@github.com:yslim-epl/shiba-yocto.git -b epl-next -m default.xml \
    --reference ~/yocto/epl-next
```

> `--dissociate`는 repo의 precious-objects 제약으로 실패한다. `--reference`만 쓰므로 **참조 대상 트리를 지우면 이 트리가 깨진다.**

로컬 매니페스트로 작업 브랜치를 덮어쓰고, 느린 원격을 https로 바꾼다. `git://git.yoctoproject.org`는 수 분씩 걸리는 반면 https는 2초다.

```bash
mkdir -p .repo/local_manifests
cat > .repo/local_manifests/build-signing-separation.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
  <remove-project name="yslim-epl/shiba-meta-secure-boot.git"/>
  <project name="yslim-epl/shiba-meta-secure-boot.git"
           path="layers/meta-st/meta-secure-boot"
           revision="build-signing-separation"
           remote="github-ssh"/>
  <remote fetch="https://git.yoctoproject.org/" name="yocto-https"/>
  <remote fetch="https://git.openembedded.org/" name="oe-https"/>
  <remove-project name="meta-security"/>
  <project name="meta-security" path="layers/meta-security"
           revision="97e482b71688b62ac1109d16e89368122f039cbf" remote="yocto-https"/>
  <remove-project name="bitbake"/>
  <project name="bitbake" path="layers/openembedded-core/bitbake"
           revision="8dcf084522b9c66a6639b5f117f554fde9b6b45a" remote="oe-https"/>
</manifest>
EOF

~/.bin/repo sync -j8 --no-clone-bundle
```

다운로드 캐시 공유(선택):

```bash
ln -sfn ~/yocto/epl-next/downloads downloads
```

---

## 5. 빌드 머신: 설정

```bash
cd ~/yocto/unsigned-build
source scripts/setup-env.sh factory-red < <(yes y)
```

> ⚠️ **`yes y | source …` 처럼 파이프를 쓰면 안 된다.** 파이프 오른쪽은 서브셸이라 bitbake PATH가 현재 셸에 남지 않는다. `< <(yes y)` 로 stdin만 넘긴다. `y`는 arm64에 존재하지 않는 `gcc-multilib` 경고를 무시하기 위한 응답이다.

`conf/local.conf` 끝에 추가:

```
SHIBA_SIGN_MODE = "unsigned"
SIGN_KEY_PATH = "/home/yslim/pubkeys-new"
SSTATE_MIRRORS = "file://.* file:///home/yslim/yocto/epl-next/sstate-cache/PATH"
```

`local.conf`는 `layer.conf`보다 나중에 파싱되므로 하드 대입이 `?=`를 덮어쓴다. 환경변수 passthrough는 필요 없다.

확인:

```bash
bitbake -e | grep -E "^(SHIBA_SIGN_MODE|SIGN_ENABLE|SIGN_KEY_PATH|UBOOT_SIGN_PUBKEY_DIR|SWU_SIGN_CERT|TF_A_SIGN_SUFFIX)="
```

기대값:

```
SHIBA_SIGN_MODE="unsigned"
SIGN_ENABLE="1"          ← 제품과 동일한 TF-A/FIP 를 만들기 위해 1 을 유지한다
SIGN_KEY_PATH="/home/yslim/pubkeys-new"
UBOOT_SIGN_PUBKEY_DIR="/home/yslim/pubkeys-new"
SWU_SIGN_CERT=".../swu-sign-3072/swu-sign-cert.pem"
TF_A_SIGN_SUFFIX=""
```

> ⚠️ `bitbake -e`는 `SIGN_KEY_PASS`를 **평문으로 출력한다.** 로그를 공유할 때 주의.

---

## 6. 빌드 머신: 빌드 (3단계)

순서가 중요하다. `swu-image-secure`는 이미지 빌드가 끝난 뒤 실행되는 전제로 만들어져 있고, 의존성을 선언하면 `bitbake swu-image-secure`가 이미지 전체 그래프(12,777 태스크)를 끌어온다.

```bash
./run bitbake                                    # 1) 이미지
./run gen-swu                                    # 2) .swu
bitbake -c prepare_sign_bundle st-image-secure   # 3) 서명 번들
```

전제조건이 안 맞으면 무엇을 먼저 실행해야 하는지 알려주며 실패한다.

산출물:

```
tmp-glibc/deploy/images/shiba-factory-red/
    sign-bundle/                       (약 1.1G)
    sign-bundle-shiba-factory-red.tar.gz   (약 908M)
    images/UNSIGNED-DO-NOT-FLASH.txt
```

번들 구성:

```
sign-bundle/
  sign.sh            서명 + 재조립 (레이어에서 옴 = 버전관리·리뷰 대상)
  bundle.conf        산출물 이름 (빌드가 생성 = 드리프트 불가)
  README.txt
  MANIFEST.sha256    전 파일 체크섬
  tools/             cert_create fiptool uboot-mkimage uboot-fit_check_sign
                     debugfs dumpe2fs e2fsck + lib/ (uninative 로더·라이브러리)
  pubkeys/           이 빌드가 실제로 심은 공개 재료
  unsigned/          서명 대상 산출물
  flashlayout/       *.tsv
```

---

## 7. 서명 머신: 수령과 서명

```bash
mkdir -p ~/incoming && cd ~/incoming
cp /mnt/machines/yocto-stm32/home/yslim/yocto/unsigned-build/build-openstlinuxweston-shiba-factory-red/tmp-glibc/deploy/images/shiba-factory-red/sign-bundle-shiba-factory-red.tar.gz .
tar xzf sign-bundle-shiba-factory-red.tar.gz
cd sign-bundle
sha256sum -c MANIFEST.sha256
```

```bash
./sign.sh --keys ~/signing-keys \
    --sign-tool ~/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32MP_SigningTool_CLI
```

6단계가 순서대로 실행된다.

| 단계 | 작업 |
|---|---|
| 1 | TF-A — `STM32MP_SigningTool_CLI`가 0으로 비어 있던 헤더 서명필드를 채운다 |
| 2 | FIP — `fiptool unpack` → `cert_create` → `fiptool create` 로 CoT 인증서 7개를 만들어 재패킹 |
| 3 | 커널 FIT — `mkimage -F -k` 로 서명하고, **키 없는 빌드가 심은 공개키로 자체 검증**한 뒤 bootfs ext4에 다시 써넣는다. 검증 대상은 `bundle.conf` 의 `UBOOT_CONTROL_DTB` — FIP 의 `HW_CONFIG` 이며 U-Boot 가 런타임에 쓰는 바로 그 파일이다 (`u-boot.dtb` 가 **아니다**) |
| 4 | `images/` — 서명본 수집 |
| 5 | flashlayout — `.tsv`를 서명본 이름으로 갱신 |
| 6 | SWU — 업데이트 파티션 갱신, `sw-description`의 `sha256` 갱신 후 CMS 재서명, 그리고 빌드와 동일한 버전 이름으로 `swupdate/swu-image-secure-<machine>-<version>.swu` 심볼릭 링크 생성 |

결과는 `signed/` 에 나온다 (약 1.6G).

```
signed/
  arm-trusted-firmware/  tf-a-*_Signed.stm32 (6개), metadata.bin
  fip/                   fip-*_Signed.bin (3개)
  images/                OTA/업데이트 에이전트가 기대하는 세트
  flashlayout/           *.tsv
  *.rootfs.ext4 / *.rootfs.ext4.verity   플래싱용 (tsv 가 참조하는 deploy 이름)
  images/                OTA용 세트 (do_install_secure_images 이름 = .rootfs 제거)
  *.swu                  서명된 업데이트 패키지
  swupdate/              swu-image-secure-<machine>-<version>.swu -> ../<위 .swu>
                         빌드 머신의 do_deploy_swu 와 같은 이름 형식
```

---

## 8. 검증

### 8.1 TF-A — 헤더에 새 ROT 공개키가 들어갔는가

```bash
STM32MP_SigningTool_CLI -dump signed/arm-trusted-firmware/tf-a-*optee-emmc_Signed.stm32
```

`ECDSA pub key` 값이 `~/signing-keys/publicKey.pem`과 일치해야 한다.

```
헤더 내장 공개키: 817e2d94198001243b0fe2608fab86808a3c4aa4b926857edd6eeed4bc5a1703
서명 머신 ROT   : 817e2d94198001243b0fe2608fab86808a3c4aa4b926857edd6eeed4bc5a1703
-> MATCH
```

### 8.2 FIP — CoT 인증서가 새 ROT 키로 서명됐는가

```bash
fiptool unpack --out /tmp/fv signed/fip/fip-*optee-emmc_Signed.bin
cd /tmp/fv
openssl x509 -in trusted-key-cert.bin -inform DER -out c.pem
openssl asn1parse -in c.pem -strparse 4 -out tbs.der -noout
sigoff=$(openssl asn1parse -in c.pem | grep "BIT STRING" | tail -1 | cut -d: -f1 | tr -d ' ')
openssl asn1parse -in c.pem -strparse $sigoff -out sig.der -noout
openssl dgst -sha256 -verify ~/signing-keys/publicKey.pem -signature sig.der tbs.der
```

```
새 ROT 공개키 : Verified OK
구 ROT 공개키 : Verification failure     ← 음성 대조
```

### 8.3 커널 FIT

```bash
debugfs -R "dump /fitImage /tmp/vfit" signed/st-image-secure-bootfs-*.ext4
# 검증 대상은 반드시 런타임 control FDT (bundle.conf 의 UBOOT_CONTROL_DTB).
# STM32MP 에서 u-boot.dtb 는 디바이스에 들어가지 않는 다른 파일이다.
. ./bundle.conf
uboot-fit_check_sign -k unsigned/u-boot/$UBOOT_CONTROL_DTB -f /tmp/vfit
```

`Signature check OK`. **개인키가 없는 빌드에서 `fdt_add_pubkey`가 인증서만으로 심은 공개키가, 나중에 개인키로 만든 서명을 검증한다** — 이 기능 전체의 핵심 증명이다.

### 8.4 SWU

```bash
cpio -id --quiet < signed/swu-image-secure-*.swu
openssl cms -verify -in sw-description.sig -inform DER -content sw-description -binary \
    -CAfile ~/signing-keys/swu-sign-3072/swu-sign-cert.pem -partial_chain -purpose any -out /dev/null
```

```
새 인증서 : CMS Verification successful
구 인증서 : certificate verify error     ← 음성 대조
```

`sw-description`의 `sha256`이 실제 cpio 멤버(압축본)와 일치하는지도 확인한다.

```bash
awk '/images:/,/scripts:/' sw-description | grep -oE '[0-9a-f]{64}'
sha256sum st-swu-partition*.ext4.gz
```

### 8.5 SWU 파티션의 `/shiba` — 파일 **집합**이 그대로인가

바뀌었는지만이 아니라 **늘어나지 않았는지**를 봐야 한다. `/shiba`는 `prepare-swu`가
`images/`(eMMC 세트)에서 채운 것이므로, 서명 후에도 파일 수가 같고 이름만
`_Signed`가 붙어야 한다.

```bash
lsshiba() { debugfs -R "ls -p /shiba" "$1" 2>/dev/null \
            | awk -F/ '{print $6}' | grep -vx -e '' -e . -e .. | sort; }

# 원본
lsshiba unsigned/swu/st-swu-partition-*.ext4 > /tmp/a.txt

# 서명본 (.swu 에서 파티션 추출)
mkdir /tmp/chk && cd /tmp/chk
cpio -id --quiet < .../signed/swu-image-secure-*.swu
gzip -dc st-swu-partition-*.ext4.gz > part.ext4
lsshiba part.ext4 > /tmp/b.txt

sed 's/_Signed//' /tmp/b.txt | sort | diff /tmp/a.txt -
```

기대: 차이 없음.

```
원본 6개 : fip-…optee-emmc.bin / metadata.bin / …bootfs….ext4.gz
           / …verity.gz / tf-a-…optee-emmc.stm32 / version.txt
서명 6개 : 위와 동일, tf-a·fip 만 _Signed
```

파일 수가 늘었다면 서명 스크립트가 원래 없던 변형(sdcard, programmer 등)까지
써 넣은 것이다. `.swu` 크기도 같이 확인한다.

### 8.5-1 `/shiba` 의 내용이 플래싱본과 **같은가**

집합이 같아도 내용이 다르면 플래싱은 되고 OTA 만 깨진다. `/shiba` 는 `prepare-swu`
가 `images/` 에서 채운 것이고, `images/` 는 `do_install_secure_images` 가 마지막으로
돈 시점에 멈춰 있다. `bitbake -c prepare_sign_bundle` 은 그 태스크를 끌어오지 않으므로
번들이 담는 deploy 산출물보다 오래된 상태일 수 있다. 커널 FIT(= dm-verity 루트 해시)만
새로 넣고 rootfs 를 그대로 두면 **업데이트한 뱅크**가 이렇게 죽는다.

```
device-mapper: verity: 253:0: metadata block 209693 is corrupted
```

`sign.sh` 는 `/shiba` 전체를 `signed/images/` 로 덮어쓴다. 확인:

```bash
cd /tmp/chk                      # 8.5 에서 만든 part.ext4 재사용
B=~/incoming/sign-bundle
for f in $(ls $B/signed/images); do
  debugfs -R "dump /shiba/$f /tmp/chk/x" part.ext4 >/dev/null 2>&1
  a=$(sha256sum /tmp/chk/x | cut -c1-20)
  b=$(sha256sum $B/signed/images/$f | cut -c1-20)
  [ "$a" = "$b" ] && r=MATCH || r="DIFFER"
  printf '  %-64s %s\n' "$f" "$r"
done
```

기대: 6개 전부 `MATCH`. 특히 verity 해시는 `signed/` 의 플래싱용 `.ext4.verity` 와도
같아야 한다 — 플래싱본과 OTA 본이 같은 rootfs 라는 뜻이다.

### 8.6 flashlayout `.tsv` 가 참조하는 파일이 전부 있는가

`sign.sh` 가 마지막에 자동으로 확인하고 하나라도 없으면 실패한다.

```
==> checking the flashlayout against what was produced
    every .tsv entry resolves
```

수동 확인:

```bash
for t in signed/flashlayout/*.tsv; do
    awk 'NR>1 && $NF != "none" {print $NF}' "$t" | sort -u | while read f; do
        [ -e "signed/$f" ] && echo "OK      $f" || echo "MISSING $f"
    done
done
```

**두 이름 규칙을 혼동하면 여기서 걸린다** — `.tsv` 는 deploy 이름(`.rootfs` 인픽스 포함)을,
`images/` 는 `do_install_secure_images` 가 쓰는 이름(인픽스 제거)을 쓴다.

```
signed/st-image-secure-bootfs-…-shiba-factory-red.rootfs.ext4         ← tsv
signed/images/st-image-secure-bootfs-…-shiba-factory-red.ext4.gz      ← OTA
```

### 8.7 버전 심볼릭 링크

빌드 머신과 같은 형식이어야 한다.

```bash
ls -l signed/swupdate/
```

```
swu-image-secure-shiba-factory-red-1.0-r112-20260827.swu
    -> ../swu-image-secure-openstlinux-weston-shiba-factory-red.rootfs.swu
```

버전 문자열은 번들에 실려 온 `unsigned/version.txt` 에서 읽는다.

---

## 9. 검증 결과 요약 (2026-08-27 실측)

| 항목 | 결과 |
|---|---|
| 빌드 머신 개인키 | **0개** (`~/STM32AP_KeyGen`까지 격리한 상태로 빌드) |
| 이미지 빌드 | 12,777 태스크 전부 성공 |
| 서명 머신 | Debian 12, 빌드 트리·bitbake·debugfs 없음 |
| 번들 무결성 | MANIFEST 60개 파일 체크섬 OK |
| TF-A 6개 | 헤더 공개키가 새 ROT 키와 **바이트 일치** |
| FIP 3개 | 엔트리 13개 / CoT 인증서 7개, 새 ROT 키로 **Verified OK**, 구 키로 실패 |
| 커널 FIT | `fit_check_sign` **OK** |
| SWU | 새 인증서로 **성공**, 구 인증서로 **실패** |
| `sw-description` sha256 | 이미지 항목 갱신됨 / 스크립트 항목 보존 |
| SWU 파티션 `/shiba` | 원본과 **파일 집합 동일**(6개), `tf-a`·`fip` 만 `_Signed` |
| flashlayout `.tsv` | 양쪽 tsv 참조 항목 **15개 전부 해석**(MISSING 0) |
| `swupdate/` 버전 링크 | 빌드 머신과 동일 형식, 서명본을 가리킴 |

---

## 10. 함정 모음

이번 검증에서 실제로 걸린 것들이다.

### 빌드

1. **`SIGN_ENABLE = 0` 금지** — 서명뿐 아니라 `TRUSTED_BOARD_BOOT`/mbedtls/`MEASURED_BOOT`까지 꺼진다.
2. **`FIT_GENERATE_KEYS = 1`** 을 키 없이 두면 bitbake가 **일회용 키를 자동 생성**해 `u-boot.dtb`에 박는다. 에러 없이 "쓰레기 키로 서명된 빌드"가 된다. `SHIBA_SIGN_MODE`가 이를 따라간다.
3. **`UBOOT_SIGN_ENABLE`은 두 모드 모두 1** 이어야 한다. `mkimage -F -k`는 **기존 signature 노드를 채울 뿐 만들지 못한다.**
4. **`fdt_add_pubkey`는 `-r` 없이** 호출해야 한다. `mkimage -f auto-conf`가 signature 노드에 `required` 속성을 쓰지 않기 때문이다.
5. **conf 파일의 `require`는 부모 파일 디렉터리 기준**이다 (`require shiba-signing.inc`, `conf/` 접두어 금지).
6. **`FLASHLAYOUT_SUFFIX`는 머신 include가 하드 `=`로 덮어쓴다** → `:forcevariable` 필요.
7. **`SIGN_KEY_PASS`가 비면** meta-st `init_keylist_from()`이 `bb.fatal`. unsigned 모드는 placeholder를 넣는다.
8. **python `:prepend`에서 early `return` 금지** — bitbake가 태스크 본문에 이어붙이므로 태스크 전체가 종료된다. `.swu` 생성이 통째로 스킵되고 끊긴 심볼릭 링크만 남는 형태로 조용히 실패했다.
9. **`swu-image-secure`는 이미지 빌드 후 실행 전제**다. 의존성을 선언하면 `bitbake swu-image-secure`가 12,777 태스크를 돌며 `st-swu-partition:do_rootfs`를 재실행한다.
10. **`do_deploy_swu`의 `after do_image_complete`는 무효**였다 — 이 레시피는 `inherit swupdate`(이미지 변형 아님)라 그 태스크가 없다. 깨끗한 트리에서 task 19/12777로 튀어나와 `version.txt not found`로 죽었다. 지금까지는 이전 빌드의 잔여 파일 덕에 가려져 있었다.
    **최종 조치는 순서 한 줄만 고치는 것이다** — 9번과 상충하지 않도록 한다:
    ```diff
    -addtask deploy_swu after do_image_complete before do_build
    +addtask deploy_swu after do_swuimage before do_build
    ```
    `do_swuimage`는 **같은 레시피 안**의 태스크라 다른 레시피를 끌어오지 않는다(비용 0). 처음에는 `do_swuimage[depends] += "st-swu-partition:do_image_complete version-info:do_deploy"` 와 `do_deploy_swu[depends] += "version-info:do_deploy"` 도 함께 넣었지만, 그러면 `bitbake swu-image-secure`가 12,777 태스크를 돌게 되어(9번) **전부 되돌렸다.** 누락된 의존성은 선언하는 대신 `do_swuimage:prepend`의 전제조건 검사로 대체했다.

### 서명 도구

11. **`STM32MP_KeyGen_CLI -ecc 1`이 도움말과 반대로 brainpool을 만든다.** 생략해야 prime256v1.
12. **`STM32MP_SigningTool_CLI`에 `-of`나 `--header-version`을 임의로 붙이면 실패한다.** 레시피는 이 둘을 넘기지 않는다. 붙이면 `Invalid Header version`(v2.17은 `1`만 받음) 또는 `Binary already contains header`가 난다. `layer.conf`의 `SIGN_HEADER_VERSION_stm32mp15="1.0"`은 TF-A 경로에서 쓰이지 않는다.
13. **ST 도구는 PKCS#11을 지원한다** (`--module` `--slot-index` `--key-index` `--active-keyIndex`). `cert_create --rot-key`도 PKCS#11 URI를 받고 `mkimage`는 `-N <engine>`이 있다 → 개인키를 HSM에 두는 선택지가 실제로 가능하다.

### 번들 이식성

14. **Yocto native 바이너리의 ELF 인터프리터는 빌드 트리 절대경로다.** 로컬에서 테스트하면 그 경로가 존재해 통과하지만, 다른 머신에서는 전부 기동 실패한다. → uninative 로더·라이브러리를 동봉하고 그것을 통해 기동한다.
15. **`ld.so --list`는 호스트 기본 경로에서도 해석한다.** "not found"만 검사하면 번들에 없는 라이브러리가 호스트 것으로 해석되며 검사가 통과한다. **모든 의존성이 번들 안에서 해석되는지**를 요구해야 한다.
16. **`find -type f`는 SONAME 심볼릭 링크를 건너뛴다** (`libext2fs.so.2` → `.so.2.4`). 로더가 찾는 이름은 링크 쪽이다.
17. **호스트 e2fsprogs 1.46.5는 `orphan_file`(FEATURE_C12)을 모른다** — 수정하지 않은 원본 이미지도 `e2fsck`가 거부한다. 이미지를 편집하는 주체이므로 e2fsprogs도 번들에 싣는다.
18. **`.swu` 멤버 이름의 `.rootfs` 인픽스**를 놓치면 서명본이 미참조 상태로 추가되고 `sw-description`은 원본을 계속 지시한다 → **유효한 서명이 붙은 채 미서명 아티팩트를 설치하는 패키지**가 된다. `sw-description`의 `sha256`은 **cpio 멤버(압축본) 기준**이며 페이로드 교체 시 반드시 갱신해야 한다.

19. **재조립은 "무엇이 바뀌었나"가 아니라 "집합이 그대로인가"로 검증해야 한다.** SWU 파티션의 `/shiba`에 서명본을 써 넣을 때, 서명된 아티팩트를 **전부** 쓰면 원래 그 패키지가 담은 적 없는 변형(sdcard, programmer-usb/uart)까지 들어간다 — 6개짜리가 13개가 됐다. `/shiba`는 `prepare-swu`가 `images/`(eMMC 세트)에서 채운 것이므로 **거기 실제로 있는 항목만 열거해서 교체**해야 한다. 짝이 없거나 이미 `_Signed`로 보이면 실패시킨다.

20. **`images/` 와 flashlayout `.tsv` 는 이름 규칙이 다르다.** `.tsv` 는 deploy 이름(`st-image-secure-bootfs-….**rootfs**.ext4`)을 쓰고, `images/` 는 `do_install_secure_images` 가 인픽스를 떼어낸 이름을 쓴다. 이걸 하나로 뭉개면 `STM32_Programmer_CLI` 가 `File does not exist: …rootfs.ext4` 로 멈춘다 — **플래싱을 시도하기 전까지 아무도 모른다.** 이름을 **조립하지 말고** deploy 에서 실제 파일을 찾아 쓰고(`resolve_deploy`, 없으면 `bbfatal`), `bundle.conf` 가 두 형태를 모두 실어 보내야 한다. 덤: verity 의 `.gz` 는 deploy 루트에 없고 **`images/` 안에만** 있다(거기서 gzip 된다).
    대응으로 `sign.sh` 마지막에 **모든 `.tsv` 항목이 실재하는지 검사**를 넣었다(8.6).

> 14·15는 "검사가 있는데 통과했다"가 가장 위험한 형태였고, 18은 `sign.sh`가 `exit 0`으로 끝났는데도 산출물이 틀렸다. 19는 검증이 "서명본으로 바뀌었는지"만 보고 "늘어나지 않았는지"를 안 봐서 놓쳤고, 20은 실제 플래싱을 시도하고서야 드러났다. **종료 코드가 아니라 산출물을 뜯어봐야 하고, 변경·집합·이름을 각각 소비처 기준으로 대조해야 한다.** 19·20 모두 스크립트 검증이 아니라 사람이 마운트하고 플래싱해 보다 나왔다.

---

## 11. 이 모델의 한계

- **SWU 검증 인증서는 dm-verity 보호 rootfs 안에 있다.** 빌드 전에 확정해야 하고 서명 단계에서 교체할 수 없다. 수령 측이 자기 키를 쓰려면 **공개 재료를 빌드 전에** 제공해야 한다.
- **ROT 공개키 해시는 OTP 퓨즈**에 들어간다. 이미지가 아니라 디바이스에 프로그래밍하며 비가역이다.
- **번들은 빌드 호스트 아키텍처에 묶인다** (여기서는 aarch64). 서명 머신도 같은 아키텍처여야 한다.
- 이번 검증 산출물은 **새 키로 서명됐고 그 PKH가 퓨징되지 않은 보드에서는 부팅하지 않는다.** 검증 대상은 절차이지 부팅이 아니다.
- rootfs/overlay 자체는 서명 대상이 아니다. verity roothash가 FIT 안에 있고 FIT이 서명되므로 보호된다.

---

## 12. 정리

```bash
orbctl delete yocto-signing          # 서명 머신 폐기
rm -rf ~/yocto/unsigned-build        # 빌드 워크스페이스
rm -rf ~/pubkeys-new                 # 공개 재료
```

`~/yocto/epl-next`는 `--reference` 대상이므로 지우면 안 된다.
