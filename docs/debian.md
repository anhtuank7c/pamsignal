# Debian official archive — submission runbook

This document covers the path from "we have a working `debian/`" to
"`apt install pamsignal` works on a stock Debian or Ubuntu install."
It's a long process — months, not days — and it involves real humans on
the Debian side. This runbook is the maintainer's checklist; the actual
upload happens through a sponsor.

For shorter-term distribution paths (the github.io repo we already
operate, or a Launchpad PPA) see the README.

## What "in Debian" means

A package "in Debian" lives in the official archive served from
`deb.debian.org`. From there:

1. New uploads land in **unstable** (Debian's rolling development tree).
2. After ~10 days with no release-critical bugs, the package migrates to
   **testing**.
3. At Debian's next stable freeze, testing becomes the next stable
   release. Maintained for ~3 years, with security backports.
4. **Ubuntu auto-syncs** unstable into Ubuntu's `universe` pocket every
   release cycle — once pamsignal is in unstable, it appears in the
   next Ubuntu release without any extra work from us.

The archive is served on every Debian/Ubuntu install by default, so
end users just `apt install pamsignal`. No third-party repo, no key
import, no PPA add. That's the prize.

## The route through mentors.debian.net

Debian's "do-ocracy" gates archive uploads behind keysigned upload
permissions:

- **Debian Developers (DD)** — full upload rights to anything in the
  archive.
- **Debian Maintainers (DM)** — upload rights to specific packages they
  maintain, granted by a DD advocate.
- **Everyone else** — no direct upload. Must go through a DD or DM as
  a *sponsor*.

We start as "everyone else." The standard path:

1. **Polish the package.** Lintian-clean, manpage present, builds in a
   clean chroot, autopkgtest if practical.
2. **Upload to mentors.debian.net.** This is a public staging area for
   sponsor candidates. The upload is signed with our personal GPG key
   (the same one in `debian/changelog`'s `Maintainer:` field).
3. **File a Request For Sponsorship (RFS) bug** against the
   `sponsorship-requests` pseudo-package on bugs.debian.org. The bug
   announces "this package on mentors needs a DD to upload it."
4. **Wait for a sponsor** to pick it up. Sponsors are volunteers and
   under no obligation; they review the package, may ask for changes,
   and (if happy) sign and upload. Realistic wait: weeks to months.
5. **NEW queue review.** First-time uploads land in NEW, where Debian's
   `ftpmaster` team manually reviews the copyright file. Another wait
   of weeks to months.
6. **Once accepted**, the package is in unstable. Done.

## Pre-flight checklist

Run through all of these before uploading. Blocking gaps in
**bold**.

### Already done
- [x] `debian/source/format` is `3.0 (quilt)` — required for archive.
- [x] `debian/control` declares `Standards-Version`, `Vcs-*`,
      `Homepage`, `Rules-Requires-Root: no`, machine-readable
      `debian/copyright` (DEP-5).
- [x] `debian/rules` uses `dh` with sane overrides (no manual `dh_*`
      gymnastics).
- [x] `debian/watch` (uscan v4) tracking GitHub release tags.
- [x] Package builds with `dpkg-buildpackage -S` (use
      `scripts/build-debian-source.sh`).

### Still TODO before mentors upload
- [ ] **Manpage.** `debian/pamsignal.8` (and arguably
      `debian/pamsignal.conf.5`). Lintian flags
      `binary-without-manpage` as a warning, and ftpmaster reviewers
      often push back on packages without one. Use `help2man` or
      hand-roll `groff` markup.
- [ ] **Bump `Standards-Version`** to the current Debian Policy
      version (check on tracker.debian.org). We're at 4.6.2 — verify
      and bump.
- [ ] **Verify clean build under `sbuild`** in a fresh chroot, not
      just `dpkg-buildpackage` on this laptop. Ubuntu's `sbuild` and
      Debian's `sbuild` use different defaults; sponsors will rebuild
      yours in a Debian sid chroot.
- [ ] **Lintian must be clean** at default severity. Run
      `lintian -i -I --pedantic ../pamsignal_X.Y.Z-1.dsc` and triage
      every tag. `--pedantic` is overkill for upload but exposes
      common reviewer pet peeves.
- [ ] **autopkgtest** (DEP-8) — not strictly required for unstable,
      but recommended. A smoke test that installs the .deb in a
      container, starts the daemon, sends a synthetic event, and
      checks `journalctl -t pamsignal` is enough.
- [ ] **Find a sponsor in advance**, not after upload. Cold uploads
      sit on mentors for weeks. Engage with the
      `debian-mentors@lists.debian.org` mailing list, IRC
      `#debian-mentors` on OFTC, or a DD whose work you respect.

## Per-release workflow

Once the pre-flight is clean and you have a sponsor in mind:

### 1. Tag and update changelog

The top entry of `debian/changelog` must target `unstable`:

```
pamsignal (X.Y.Z-1) unstable; urgency=medium

  * Describe what changed for THIS Debian upload — sponsors read this
    as the first thing in the review. Don't paste the whole upstream
    CHANGELOG.

 -- Tuan Nguyen <anhtuank7c@hotmail.com>  <RFC2822 timestamp>
```

The Debian revision (`-1`, `-2`, …) increments only when re-uploading
the *same upstream version* (e.g., to fix a packaging bug). For new
upstream releases, reset to `-1`.

### 2. Build the signed source package

```bash
scripts/build-debian-source.sh
```

The script will:

- generate `../pamsignal_X.Y.Z.orig.tar.xz` from `git archive HEAD`
  (skipped if the file already exists);
- stage an isolated build tree in `$TMPDIR`;
- run `dpkg-buildpackage -S -sa`, prompting for your GPG passphrase to
  sign `pamsignal_X.Y.Z-1.dsc` and `_source.changes`.

### 3. Lintian

```bash
lintian -i -I ../pamsignal_X.Y.Z-1.dsc
```

Treat all `E:` (errors) as blockers. Triage `W:` (warnings) — most
should be addressed; a small number are acceptable with override
files (`debian/source.lintian-overrides`) if justified.

### 4. Configure dput for mentors

Add to `~/.dput.cf` (one-time setup):

```ini
[mentors]
fqdn = mentors.debian.net
incoming = /upload
method = https
allow_unsigned_uploads = 0
progress_indicator = 2
allowed_distributions = .*
```

### 5. Upload

```bash
dput mentors ../pamsignal_X.Y.Z-1_source.changes
```

mentors.debian.net emails an `Accepted` (or `Rejected` with reason)
notification. The package then shows up at
<https://mentors.debian.net/package/pamsignal/>.

### 6. File the RFS bug

```bash
reportbug --no-config-files --package-version=X.Y.Z-1 \
          --severity=normal sponsorship-requests
```

Subject: `RFS: pamsignal/X.Y.Z-1 [ITP] -- Real-time PAM login monitor`

Body template — fill in the `[brackets]`:

```
Dear mentors,

I am looking for a sponsor for my package "pamsignal":

 * Package name    : pamsignal
 * Version         : X.Y.Z-1
 * Upstream author : Tuan Nguyen <anhtuank7c@hotmail.com>
 * URL             : https://github.com/anhtuank7c/pamsignal
 * License         : MIT
 * Vcs             : https://github.com/anhtuank7c/pamsignal
 * Section         : admin

The package builds on the current debian unstable.

It builds these binary packages:
  pamsignal - Real-time PAM login monitor with multi-channel alerts

To access further information about this package, visit:
  https://mentors.debian.net/package/pamsignal/

Alternatively, you can download the package with dget:
  dget -x https://mentors.debian.net/debian/pool/main/p/pamsignal/pamsignal_X.Y.Z-1.dsc

Changes since the last upload:
  [paste the changelog entry from step 1]

Regards,
  Tuan Nguyen
```

### 7. Wait for a sponsor

Sponsors browse <https://mentors.debian.net/sponsor/> and pick
packages that catch their eye. To improve odds:

- Engage on `#debian-mentors` (OFTC) — mention the RFS bug number.
- Post the RFS to `debian-mentors@lists.debian.org`.
- Address any reviewer comments quickly; cold packages get archived.

### 8. After upload to unstable

Once a sponsor uploads, the package enters NEW (first time only).
Track at <https://ftp-master.debian.org/new.html>. ftpmaster review
is on copyright correctness primarily; expect 2-8 weeks.

After NEW: package is in unstable. Watch the Debian Package Tracker
(<https://tracker.debian.org/pkg/pamsignal>) for build failures,
piuparts results, autopkgtest results, and migration progress.

## Subsequent uploads

After the first sponsored upload, subsequent uploads of the same
package are easier:

1. Same workflow as above (steps 1-5), but the RFS bug just references
   the previous one.
2. After ~3 successful sponsored uploads, the same sponsor (or another
   DD who's reviewed your work) can advocate you for **Debian
   Maintainer** status — at that point you upload directly without an
   RFS, for `pamsignal` specifically.

## When a sponsor asks for changes

Common requests:

- **`d/copyright` is incomplete** — you missed a third-party file's
  license. Inspect every file with a license header; DEP-5 the result.
- **`d/control` Description field is too short / repeats the synopsis**
  — write a paragraph that tells the reader what the package *does*,
  not what its tagline says.
- **Hardening flags missing from build** — Debian's `dpkg-buildflags`
  already injects them; we use `DEB_BUILD_MAINT_OPTIONS = hardening=+all`
  in `debian/rules`. Verify with `hardening-check obj-debian/pamsignal`.
- **Symbols file missing** — only relevant for shared libraries; we
  don't ship one, so this won't apply.
- **Test runs at build time but doesn't gate `nocheck`** — `debian/rules`
  must respect `DEB_BUILD_OPTIONS=nocheck` and skip `meson test` then.
  Currently `override_dh_auto_test` always runs. Add a guard:

  ```make
  override_dh_auto_test:
  ifeq (,$(filter nocheck,$(DEB_BUILD_OPTIONS)))
      meson test -C obj-debian
  endif
  ```

## Rough timeline

| Phase | Duration | Status |
|---|---|---|
| Pre-flight polish (manpage, lintian) | 1-3 days | TODO |
| Find sponsor | 1-8 weeks | TODO |
| Sponsor review + upload | 1-4 weeks | TODO |
| NEW queue review | 2-8 weeks | TODO |
| In unstable | — | done |
| Migrate to testing | ~10 days | auto |
| Next Debian stable | up to 2 years | auto |
| Synced into next Ubuntu LTS | up to 2 years | auto |

Set expectations accordingly. The github.io repo continues serving
users in the meantime.
