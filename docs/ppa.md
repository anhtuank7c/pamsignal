# Launchpad PPA — release runbook

This document walks through publishing pamsignal as a Personal Package
Archive (PPA) on Launchpad. A PPA is hosted by Canonical, signed with a
Launchpad-managed key, and discoverable via `add-apt-repository`. It's
the path of least resistance for shipping `apt install pamsignal` to
Ubuntu users without running our own apt repository.

For context on alternatives (Debian official archive, Snap Store, etc.)
see the project README.

## One-time setup

These steps configure your Launchpad account and PPA. You only do them
once per maintainer.

### 1. Launchpad account + PPA

1. Sign in at <https://launchpad.net> (uses your Ubuntu One / SSO
   account).
2. Sign the **Ubuntu Code of Conduct**:
   <https://launchpad.net/codeofconduct>. Required before you can host
   a PPA. You'll need to sign it with the same GPG key you'll later
   use to sign uploads — see step 3.
3. Register the PPA:
   - Go to your profile page → **Create a new PPA**.
   - Name it `pamsignal`. The full PPA reference will then be
     `ppa:<your-launchpad-id>/pamsignal`.
   - Description: copy the README's tagline.

### 2. GPG key

Launchpad needs a GPG key to verify your source uploads. The key must
match the `Maintainer:` field in `debian/control`
(`Tuan Nguyen <anhtuank7c@hotmail.com>`).

```bash
# Skip if you already have a key. Use 4096-bit RSA, no expiry — or set a
# rotation policy you'll actually follow.
gpg --full-generate-key   # choose RSA 4096, 0 = no expiry

# List keys to find the fingerprint
gpg --list-secret-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}'

# Export the public half and upload to the SKS keyserver Launchpad reads
gpg --keyserver keyserver.ubuntu.com --send-keys <FINGERPRINT>
```

Then in Launchpad: **Profile → OpenPGP keys → Import an OpenPGP key** —
paste the fingerprint. Launchpad emails you an encrypted token; decrypt
and click the link inside to confirm.

### 3. Local tooling

```bash
sudo apt install devscripts dput debhelper lintian
```

- `devscripts` provides `debchange` / `debsign`.
- `dput` uploads source packages.
- `lintian` is the Debian policy linter — run it locally before upload
  to catch issues before they bounce off Launchpad.

### 4. dput config (optional)

`dput` works out of the box for `ppa:` hosts but you can customize
upload behavior in `~/.dput.cf`:

```ini
[my-pamsignal-ppa]
fqdn = ppa.launchpad.net
method = ftp
incoming = ~anhtuank7c/ubuntu/pamsignal/
login = anonymous
allow_unsigned_uploads = 0
```

## Per-release workflow

Each upstream version (`X.Y.Z`) ships as one signed source package
*per Ubuntu release*. The orig tarball is shared across releases; only
the `debian.tar.xz` differs (because the Ubuntu codename in
`debian/changelog` is part of the source package).

### 1. Tag the upstream release

This step is shared with the github.io / Debian-archive paths — there's
nothing PPA-specific. Cut the tag and push it as documented elsewhere.

### 2. Build the signed source package

```bash
# From the project root, with a clean working tree at the release tag:
scripts/build-ppa-source.sh noble
```

Replace `noble` with the target Ubuntu codename. The script will:

- generate `../pamsignal_X.Y.Z.orig.tar.xz` from `git archive HEAD`
  (reused from a previous codename's run if already present);
- stage an isolated build tree in `$TMPDIR`;
- rewrite the top entry of `debian/changelog` to
  `pamsignal (X.Y.Z-1~<codename>1) <codename>; urgency=medium`;
- run `dpkg-buildpackage -S -sa`, prompting for your GPG passphrase to
  sign the resulting `.dsc` and `_source.changes`;
- copy the resulting source-package files to the project's parent
  directory.

For a local sanity-check build that doesn't sign (and so doesn't need
your GPG passphrase), pass `--no-sign`. The unsigned artifacts will be
rejected by Launchpad — only use this mode to verify the build succeeds.

### 3. (Recommended) Run lintian

```bash
lintian -i -I ../pamsignal_X.Y.Z-1~<codename>1.dsc
```

`-i` shows the long-form description for each tag; `-I` includes
informational tags. Fix anything that looks blocking before upload.
Common warnings that are fine for a PPA: `binary-without-manpage`,
`source-is-missing`. Anything tagged `E:` (error) must be fixed.

### 4. Upload to Launchpad

```bash
dput ppa:anhtuank7c/pamsignal \
     ../pamsignal_X.Y.Z-1~<codename>1_source.changes
```

The script prints this exact command at the end of step 2.

After upload Launchpad emails you an `Accepted` (or `Rejected`)
notification within ~1 minute. Accepted source packages go to the build
queue; binary builds take ~30 min per architecture (PPAs default to
amd64 + arm64). When the build finishes you'll get a second email and
the package appears in the PPA's package list.

### 5. Repeat for every supported Ubuntu release

Run the script once per codename:

```bash
scripts/build-ppa-source.sh jammy     # 22.04 LTS
dput ppa:anhtuank7c/pamsignal ../pamsignal_X.Y.Z-1~jammy1_source.changes

scripts/build-ppa-source.sh noble     # 24.04 LTS
dput ppa:anhtuank7c/pamsignal ../pamsignal_X.Y.Z-1~noble1_source.changes

scripts/build-ppa-source.sh resolute  # 26.04 LTS
dput ppa:anhtuank7c/pamsignal ../pamsignal_X.Y.Z-1~resolute1_source.changes
```

The same upstream tarball is reused — only the per-codename
`debian.tar.xz` changes — so the second and third uploads are seconds
of CPU each.

## End-user install instructions

Once the PPA has built binaries for at least one Ubuntu release, users
install with:

```bash
sudo add-apt-repository ppa:anhtuank7c/pamsignal
sudo apt update
sudo apt install pamsignal
```

`add-apt-repository` automatically imports the Launchpad-managed signing
key — the user doesn't need to handle the key separately, unlike the
github.io path.

## Why `~codenameN` revisions?

The convention `pamsignal (0.2.2-1~noble1)` parses, by Debian version
ordering rules, as **lower than** `pamsignal (0.2.2-1)`. This matters
because:

1. If pamsignal eventually lands in the Debian archive, the unsuffixed
   version `0.2.2-1` will sync into Ubuntu's `universe` pocket. Your
   PPA's `0.2.2-1~noble1` then sorts below the official version, so
   `apt` automatically prefers the official package on upgrade.
2. If you re-roll a single Ubuntu release (say you find a packaging
   bug), bump the trailing digit: `~noble1` → `~noble2`. Same upstream,
   same orig tarball, only debian.tar.xz changes.

## Troubleshooting

**`dput: Upload rejected: pamsignal_..._source.changes is not signed.`**
Run the build script without `--no-sign`, or sign manually:
`debsign ../pamsignal_X.Y.Z-1~<codename>1_source.changes`.

**`gpg: signing failed: Inappropriate ioctl for device`**
GPG can't prompt because `dpkg-buildpackage` runs without a TTY. Either
unlock your key in `gpg-agent` first (`echo | gpg --clearsign /dev/null`
to trigger a passphrase cache) or set `GPG_TTY=$(tty)` in your shell
profile.

**Launchpad rejects with `Unable to find distroseries: <codename>`**
The codename isn't a valid Ubuntu release. Update the supported list
in `scripts/build-ppa-source.sh` if Canonical has shipped a new one.

**Build succeeds in the PPA queue but the binary doesn't appear**
Check the PPA's **build status** page for that source upload — it'll
show stderr from `dpkg-buildpackage -b` on Launchpad's builder. Common
causes: a build-dependency that's in your local Ubuntu but not in the
target release (debhelper version skew is the usual culprit).
