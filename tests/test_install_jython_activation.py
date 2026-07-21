"""
Tests for install.py's _activate_jython_extension.

Ghidra 12.1 ships Jython as an inert extension archive under
<install>/Extensions/Ghidra/*Jython*.zip. The installer must extract it into
the install-tree extensions dir <install>/Ghidra/Extensions/ so analyzeHeadless
can load it. These tests pin the source and destination paths so a regression
back to globbing the destination for the source (which silently no-ops) is
caught.
"""

import zipfile

import install


def _make_ghidra_with_bundled_zip(base_dir, *, jython_member="Jython/lib/jython-standalone.jar"):
    """Create a fake Ghidra install whose bundled Jython zip sits at the real
    location: <install>/Extensions/Ghidra/ghidra_12.1_PUBLIC_Jython.zip."""
    ghidra_dir = base_dir / "ghidra"
    bundled_dir = ghidra_dir / "Extensions" / "Ghidra"
    bundled_dir.mkdir(parents=True)
    # Install-tree extensions dir exists in a real distribution.
    (ghidra_dir / "Ghidra" / "Extensions").mkdir(parents=True)

    zip_path = bundled_dir / "ghidra_12.1_PUBLIC_Jython.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        # Extension zips contain a single top-level dir named after the extension.
        zf.writestr(jython_member, b"PK\x03\x04stub-jar")
    return ghidra_dir


def test_activate_extracts_bundled_zip_into_install_tree(tmp_path, capsys):
    ghidra_dir = _make_ghidra_with_bundled_zip(tmp_path)

    install._activate_jython_extension(ghidra_dir)

    extracted = ghidra_dir / "Ghidra" / "Extensions" / "Jython" / "lib" / "jython-standalone.jar"
    assert extracted.is_file(), "Jython jar should be extracted into the install tree"
    assert "Jython extension activated" in capsys.readouterr().out


def test_activate_is_idempotent_when_already_installed(tmp_path, capsys):
    ghidra_dir = _make_ghidra_with_bundled_zip(tmp_path)
    # Pretend it's already activated.
    (ghidra_dir / "Ghidra" / "Extensions" / "Jython").mkdir(parents=True)

    install._activate_jython_extension(ghidra_dir)

    assert "already activated" in capsys.readouterr().out


def test_activate_noop_when_no_bundled_zip(tmp_path, capsys):
    """Pre-12.1 (or BYO Ghidra) has no bundled zip -> no-op, no Jython dir."""
    ghidra_dir = tmp_path / "ghidra"
    (ghidra_dir / "Ghidra" / "Extensions").mkdir(parents=True)
    (ghidra_dir / "Extensions" / "Ghidra").mkdir(parents=True)

    install._activate_jython_extension(ghidra_dir)

    assert not (ghidra_dir / "Ghidra" / "Extensions" / "Jython").exists()
    assert "No bundled Jython extension found" in capsys.readouterr().out
