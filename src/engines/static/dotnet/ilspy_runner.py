"""
ILSpyCmd runner for cross-platform .NET decompilation.

Provides a wrapper around ILSpyCmd (the CLI version of ILSpy) for
decompiling .NET assemblies to C# source code.
"""

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DotNetTypeInfo:
    """Information about a .NET type (class, struct, interface, enum)."""
    name: str
    namespace: str
    full_name: str
    kind: str  # class, struct, interface, enum, delegate
    base_type: str = ""
    interfaces: list = field(default_factory=list)
    is_public: bool = True
    is_abstract: bool = False
    is_sealed: bool = False
    is_static: bool = False
    methods: list = field(default_factory=list)
    properties: list = field(default_factory=list)
    fields: list = field(default_factory=list)
    nested_types: list = field(default_factory=list)


@dataclass
class DotNetMethodInfo:
    """Information about a .NET method."""
    name: str
    return_type: str
    parameters: list = field(default_factory=list)
    is_public: bool = True
    is_static: bool = False
    is_virtual: bool = False
    is_abstract: bool = False


@dataclass
class DotNetAssemblyInfo:
    """Information about a .NET assembly."""
    name: str
    version: str = ""
    target_framework: str = ""
    runtime_version: str = ""
    entry_point: str = ""
    references: list = field(default_factory=list)
    types: list = field(default_factory=list)
    type_count: int = 0
    method_count: int = 0


class ILSpyRunner:
    """
    Cross-platform ILSpyCmd wrapper for .NET decompilation.

    Supports Windows, Linux, and macOS with automatic tool detection.
    """

    def __init__(self, cache_dir: Path | None = None):
        """
        Initialize ILSpy runner.

        Args:
            cache_dir: Directory for caching decompilation results.
                      Defaults to ~/.dotnet_mcp_cache/
        """
        self.system = platform.system()
        self.cache_dir = cache_dir or Path.home() / ".dotnet_mcp_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self._ilspycmd_path: str | None = None
        self._dotnet_path: str | None = None

        logger.info(f"Initialized ILSpy runner on {self.system}")
        logger.info(f"Cache directory: {self.cache_dir}")

    def _find_ilspycmd(self) -> str | None:
        """
        Find ILSpyCmd executable.

        Checks:
        1. ilspycmd in PATH (if installed as global dotnet tool)
        2. Common installation locations

        Returns:
            Path to ilspycmd or None if not found
        """
        if self._ilspycmd_path:
            return self._ilspycmd_path

        # Check if ilspycmd is in PATH
        ilspycmd = shutil.which("ilspycmd")
        if ilspycmd:
            self._ilspycmd_path = ilspycmd
            logger.info(f"Found ilspycmd in PATH: {ilspycmd}")
            return ilspycmd

        # Check common dotnet tool locations
        home = Path.home()
        tool_paths = []

        if self.system == "Windows":
            tool_paths = [
                home / ".dotnet" / "tools" / "ilspycmd.exe",
                Path(os.environ.get("USERPROFILE", "")) / ".dotnet" / "tools" / "ilspycmd.exe",
            ]
        else:  # Linux/macOS
            tool_paths = [
                home / ".dotnet" / "tools" / "ilspycmd",
                Path("/usr/local/bin/ilspycmd"),
                Path("/usr/bin/ilspycmd"),
            ]

        for path in tool_paths:
            if path.exists():
                self._ilspycmd_path = str(path)
                logger.info(f"Found ilspycmd at: {path}")
                return self._ilspycmd_path

        logger.warning("ilspycmd not found. Install with: dotnet tool install -g ilspycmd")
        return None

    def _find_dotnet(self) -> str | None:
        """
        Find dotnet CLI.

        Returns:
            Path to dotnet or None if not found
        """
        if self._dotnet_path:
            return self._dotnet_path

        dotnet = shutil.which("dotnet")
        if dotnet:
            self._dotnet_path = dotnet
            return dotnet

        # Check common locations
        if self.system == "Windows":
            paths = [
                Path(os.environ.get("ProgramFiles", "")) / "dotnet" / "dotnet.exe",
                Path("C:\\Program Files\\dotnet\\dotnet.exe"),
            ]
        else:
            paths = [
                Path("/usr/share/dotnet/dotnet"),
                Path("/usr/local/share/dotnet/dotnet"),
                Path.home() / ".dotnet" / "dotnet",
            ]

        for path in paths:
            if path.exists():
                self._dotnet_path = str(path)
                return self._dotnet_path

        return None

    def is_available(self) -> bool:
        """Check if ILSpyCmd is available."""
        return self._find_ilspycmd() is not None

    def get_version(self) -> str | None:
        """Get ILSpyCmd version."""
        ilspycmd = self._find_ilspycmd()
        if not ilspycmd:
            return None

        try:
            result = subprocess.run(
                [ilspycmd, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip() or result.stderr.strip()
        except Exception as e:
            logger.error(f"Failed to get ilspycmd version: {e}")
            return None

    def _get_cache_key(self, assembly_path: Path) -> str:
        """Generate cache key from assembly file hash."""
        sha256 = hashlib.sha256()
        with open(assembly_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()[:16]

    def _get_cached(self, assembly_path: Path, cache_type: str) -> dict | None:
        """
        Get cached analysis results.

        Args:
            assembly_path: Path to assembly
            cache_type: Type of cache (e.g., "types", "decompiled")

        Returns:
            Cached data or None
        """
        cache_key = self._get_cache_key(assembly_path)
        cache_file = self.cache_dir / f"{cache_key}_{cache_type}.json"

        if cache_file.exists():
            try:
                with open(cache_file, encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"Cache hit for {assembly_path.name} ({cache_type})")
                return data
            except Exception as e:
                logger.warning(f"Failed to read cache: {e}")

        return None

    def _save_cache(self, assembly_path: Path, cache_type: str, data: dict) -> None:
        """Save analysis results to cache."""
        cache_key = self._get_cache_key(assembly_path)
        cache_file = self.cache_dir / f"{cache_key}_{cache_type}.json"

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.info(f"Cached {cache_type} for {assembly_path.name}")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    def list_types(
        self,
        assembly_path: str | Path,
        force_refresh: bool = False
    ) -> DotNetAssemblyInfo:
        """
        List all types in a .NET assembly.

        Args:
            assembly_path: Path to .NET assembly (.exe or .dll)
            force_refresh: Force refresh even if cached

        Returns:
            DotNetAssemblyInfo with type information

        Raises:
            FileNotFoundError: If assembly not found
            RuntimeError: If ILSpyCmd not available or fails
        """
        assembly_path = Path(assembly_path)

        if not assembly_path.exists():
            raise FileNotFoundError(f"Assembly not found: {assembly_path}")

        # Check cache
        if not force_refresh:
            cached = self._get_cached(assembly_path, "types")
            if cached:
                return self._dict_to_assembly_info(cached)

        ilspycmd = self._find_ilspycmd()
        if not ilspycmd:
            raise RuntimeError(
                "ILSpyCmd not found. Install with: dotnet tool install -g ilspycmd"
            )

        logger.info(f"Listing types in {assembly_path.name}")

        try:
            # Use -l flag to list types
            result = subprocess.run(
                [ilspycmd, str(assembly_path), "-l"],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                raise RuntimeError(f"ILSpyCmd failed: {result.stderr}")

            # Parse type listing
            assembly_info = self._parse_type_listing(
                result.stdout,
                assembly_path.name
            )

            # Cache results
            self._save_cache(
                assembly_path,
                "types",
                self._assembly_info_to_dict(assembly_info)
            )

            return assembly_info

        except subprocess.TimeoutExpired:
            raise RuntimeError("ILSpyCmd timed out while listing types")
        except Exception as e:
            logger.error(f"Failed to list types: {e}")
            raise RuntimeError(f"Failed to list types: {e}")

    def _parse_type_listing(self, output: str, assembly_name: str) -> DotNetAssemblyInfo:
        """Parse ILSpyCmd -l output to extract type information."""
        types = []

        # ILSpyCmd -l outputs fully qualified type names, one per line
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse namespace and type name
            if "." in line:
                parts = line.rsplit(".", 1)
                namespace = parts[0]
                name = parts[1]
            else:
                namespace = ""
                name = line

            # Determine type kind from naming conventions
            kind = "class"
            if name.startswith("I") and len(name) > 1 and name[1].isupper():
                kind = "interface"
            elif name.endswith("Enum") or "<" not in name and name.isupper():
                kind = "enum"
            elif name.endswith("Delegate") or name.endswith("EventHandler"):
                kind = "delegate"
            elif name.endswith("Struct"):
                kind = "struct"

            types.append(DotNetTypeInfo(
                name=name,
                namespace=namespace,
                full_name=line,
                kind=kind
            ))

        return DotNetAssemblyInfo(
            name=assembly_name,
            types=types,
            type_count=len(types)
        )

    def decompile_assembly(
        self,
        assembly_path: str | Path,
        output_dir: Path | None = None,
        force_refresh: bool = False
    ) -> Path:
        """
        Decompile entire assembly to C# source files.

        Args:
            assembly_path: Path to .NET assembly
            output_dir: Output directory (default: cache/decompiled/<hash>/)
            force_refresh: Force re-decompilation

        Returns:
            Path to output directory containing C# files

        Raises:
            FileNotFoundError: If assembly not found
            RuntimeError: If ILSpyCmd not available or fails
        """
        assembly_path = Path(assembly_path)

        if not assembly_path.exists():
            raise FileNotFoundError(f"Assembly not found: {assembly_path}")

        ilspycmd = self._find_ilspycmd()
        if not ilspycmd:
            raise RuntimeError(
                "ILSpyCmd not found. Install with: dotnet tool install -g ilspycmd"
            )

        # Determine output directory
        cache_key = self._get_cache_key(assembly_path)
        if output_dir is None:
            output_dir = self.cache_dir / "decompiled" / cache_key

        # Check if already decompiled
        if output_dir.exists() and not force_refresh:
            cs_files = list(output_dir.glob("**/*.cs"))
            if cs_files:
                logger.info(f"Using cached decompilation: {output_dir}")
                return output_dir

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Decompiling {assembly_path.name} to {output_dir}")

        try:
            start_time = time.time()

            result = subprocess.run(
                [ilspycmd, str(assembly_path), "-o", str(output_dir)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            elapsed = time.time() - start_time

            if result.returncode != 0:
                raise RuntimeError(f"ILSpyCmd failed: {result.stderr}")

            logger.info(f"Decompilation complete in {elapsed:.2f}s")

            return output_dir

        except subprocess.TimeoutExpired:
            raise RuntimeError("ILSpyCmd timed out during decompilation")
        except Exception as e:
            logger.error(f"Decompilation failed: {e}")
            raise RuntimeError(f"Decompilation failed: {e}")

    def decompile_type(
        self,
        assembly_path: str | Path,
        type_name: str
    ) -> str:
        """
        Decompile a specific type to C# source code.

        Args:
            assembly_path: Path to .NET assembly
            type_name: Fully qualified type name (e.g., "Namespace.ClassName")

        Returns:
            C# source code as string

        Raises:
            FileNotFoundError: If assembly not found
            RuntimeError: If ILSpyCmd not available or fails
        """
        assembly_path = Path(assembly_path)

        if not assembly_path.exists():
            raise FileNotFoundError(f"Assembly not found: {assembly_path}")

        ilspycmd = self._find_ilspycmd()
        if not ilspycmd:
            raise RuntimeError(
                "ILSpyCmd not found. Install with: dotnet tool install -g ilspycmd"
            )

        logger.info(f"Decompiling type {type_name} from {assembly_path.name}")

        try:
            result = subprocess.run(
                [ilspycmd, str(assembly_path), "-t", type_name],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                # Check if type not found
                if "not found" in result.stderr.lower():
                    raise ValueError(f"Type '{type_name}' not found in assembly")
                raise RuntimeError(f"ILSpyCmd failed: {result.stderr}")

            return result.stdout

        except subprocess.TimeoutExpired:
            raise RuntimeError("ILSpyCmd timed out during type decompilation")
        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Type decompilation failed: {e}")
            raise RuntimeError(f"Type decompilation failed: {e}")

    def get_il_code(
        self,
        assembly_path: str | Path,
        type_name: str | None = None
    ) -> str:
        """
        Get IL (Intermediate Language) disassembly.

        Args:
            assembly_path: Path to .NET assembly
            type_name: Optional type to disassemble (all if None)

        Returns:
            IL disassembly as string
        """
        assembly_path = Path(assembly_path)

        if not assembly_path.exists():
            raise FileNotFoundError(f"Assembly not found: {assembly_path}")

        ilspycmd = self._find_ilspycmd()
        if not ilspycmd:
            raise RuntimeError(
                "ILSpyCmd not found. Install with: dotnet tool install -g ilspycmd"
            )

        logger.info(f"Getting IL for {assembly_path.name}")

        try:
            cmd = [ilspycmd, str(assembly_path), "--il"]
            if type_name:
                cmd.extend(["-t", type_name])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                raise RuntimeError(f"ILSpyCmd failed: {result.stderr}")

            return result.stdout

        except subprocess.TimeoutExpired:
            raise RuntimeError("ILSpyCmd timed out during IL disassembly")
        except Exception as e:
            logger.error(f"IL disassembly failed: {e}")
            raise RuntimeError(f"IL disassembly failed: {e}")

    def search_types(
        self,
        assembly_path: str | Path,
        pattern: str
    ) -> list[DotNetTypeInfo]:
        """
        Search for types matching a pattern.

        Args:
            assembly_path: Path to .NET assembly
            pattern: Regex pattern to match type names

        Returns:
            List of matching types
        """
        assembly_info = self.list_types(assembly_path)

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

        matches = [
            t for t in assembly_info.types
            if regex.search(t.full_name) or regex.search(t.name)
        ]

        return matches

    def diagnose(self) -> dict:
        """
        Run diagnostic checks on ILSpyCmd installation.

        Returns:
            Diagnostic information dict
        """
        diag = {
            "platform": self.system,
            "ilspycmd_found": False,
            "ilspycmd_path": None,
            "ilspycmd_version": None,
            "dotnet_found": False,
            "dotnet_path": None,
            "dotnet_version": None,
            "cache_dir": str(self.cache_dir),
            "cache_dir_exists": self.cache_dir.exists(),
        }

        # Check ilspycmd
        ilspycmd = self._find_ilspycmd()
        if ilspycmd:
            diag["ilspycmd_found"] = True
            diag["ilspycmd_path"] = ilspycmd
            diag["ilspycmd_version"] = self.get_version()

        # Check dotnet
        dotnet = self._find_dotnet()
        if dotnet:
            diag["dotnet_found"] = True
            diag["dotnet_path"] = dotnet
            try:
                result = subprocess.run(
                    [dotnet, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                diag["dotnet_version"] = result.stdout.strip()
            except Exception:
                pass

        return diag

    def _assembly_info_to_dict(self, info: DotNetAssemblyInfo) -> dict:
        """Convert DotNetAssemblyInfo to dict for caching."""
        return {
            "name": info.name,
            "version": info.version,
            "target_framework": info.target_framework,
            "runtime_version": info.runtime_version,
            "entry_point": info.entry_point,
            "references": info.references,
            "type_count": info.type_count,
            "method_count": info.method_count,
            "types": [
                {
                    "name": t.name,
                    "namespace": t.namespace,
                    "full_name": t.full_name,
                    "kind": t.kind,
                    "base_type": t.base_type,
                    "interfaces": t.interfaces,
                    "is_public": t.is_public,
                    "is_abstract": t.is_abstract,
                    "is_sealed": t.is_sealed,
                    "is_static": t.is_static,
                }
                for t in info.types
            ]
        }

    def _dict_to_assembly_info(self, data: dict) -> DotNetAssemblyInfo:
        """Convert dict to DotNetAssemblyInfo from cache."""
        types = [
            DotNetTypeInfo(
                name=t["name"],
                namespace=t["namespace"],
                full_name=t["full_name"],
                kind=t["kind"],
                base_type=t.get("base_type", ""),
                interfaces=t.get("interfaces", []),
                is_public=t.get("is_public", True),
                is_abstract=t.get("is_abstract", False),
                is_sealed=t.get("is_sealed", False),
                is_static=t.get("is_static", False),
            )
            for t in data.get("types", [])
        ]

        return DotNetAssemblyInfo(
            name=data["name"],
            version=data.get("version", ""),
            target_framework=data.get("target_framework", ""),
            runtime_version=data.get("runtime_version", ""),
            entry_point=data.get("entry_point", ""),
            references=data.get("references", []),
            types=types,
            type_count=data.get("type_count", len(types)),
            method_count=data.get("method_count", 0),
        )


# Module-level instance for convenience
_runner: ILSpyRunner | None = None


def get_ilspy_runner() -> ILSpyRunner:
    """Get or create the singleton ILSpy runner."""
    global _runner
    if _runner is None:
        _runner = ILSpyRunner()
    return _runner
