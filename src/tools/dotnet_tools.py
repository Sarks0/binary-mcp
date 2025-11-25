"""
.NET analysis MCP tools using ILSpyCmd.

Provides decompilation and analysis capabilities for .NET assemblies,
complementing the Ghidra-based analysis for native binaries.
"""

import logging
from pathlib import Path

from fastmcp import FastMCP

from src.engines.static.dotnet.ilspy_runner import get_ilspy_runner

logger = logging.getLogger(__name__)


def register_dotnet_tools(app: FastMCP) -> None:
    """
    Register .NET analysis tools with the MCP server.

    Args:
        app: FastMCP application instance
    """
    # Initialize the ILSpy runner
    ilspy = get_ilspy_runner()

    @app.tool()
    def analyze_dotnet(
        assembly_path: str,
        force_refresh: bool = False
    ) -> str:
        """
        Analyze a .NET assembly and list all types.

        This is the entry point for .NET analysis. It extracts all types
        (classes, interfaces, enums, structs) from the assembly.

        Args:
            assembly_path: Path to .NET assembly (.exe or .dll)
            force_refresh: Force re-analysis even if cached

        Returns:
            Assembly overview with type listing

        Example:
            analyze_dotnet("C:/samples/malware.exe")
        """
        try:
            # Check if ILSpyCmd is available
            if not ilspy.is_available():
                return """**Error: ILSpyCmd not installed**

ILSpyCmd is required for .NET analysis. Install it with:

```bash
dotnet tool install -g ilspycmd
```

**Prerequisites:**
- .NET 6.0+ SDK: https://dotnet.microsoft.com/download

After installation, restart your MCP client.
"""

            path = Path(assembly_path)
            if not path.exists():
                return f"Error: Assembly not found: {assembly_path}"

            # Get assembly info
            assembly_info = ilspy.list_types(assembly_path, force_refresh)

            # Group types by namespace
            by_namespace: dict = {}
            for t in assembly_info.types:
                ns = t.namespace or "(global)"
                if ns not in by_namespace:
                    by_namespace[ns] = []
                by_namespace[ns].append(t)

            # Build output
            result = f"""**.NET Assembly Analysis: {assembly_info.name}**

**Statistics:**
- Total Types: {assembly_info.type_count}
- Namespaces: {len(by_namespace)}

**Types by Namespace:**

"""
            # Show types grouped by namespace
            for ns in sorted(by_namespace.keys()):
                types = by_namespace[ns]
                result += f"### {ns} ({len(types)} types)\n\n"

                # Group by kind
                classes = [t for t in types if t.kind == "class"]
                interfaces = [t for t in types if t.kind == "interface"]
                enums = [t for t in types if t.kind == "enum"]
                structs = [t for t in types if t.kind == "struct"]
                delegates = [t for t in types if t.kind == "delegate"]

                if classes:
                    result += f"**Classes:** {', '.join(t.name for t in classes[:10])}"
                    if len(classes) > 10:
                        result += f" ... (+{len(classes) - 10} more)"
                    result += "\n"

                if interfaces:
                    result += f"**Interfaces:** {', '.join(t.name for t in interfaces[:10])}"
                    if len(interfaces) > 10:
                        result += f" ... (+{len(interfaces) - 10} more)"
                    result += "\n"

                if enums:
                    result += f"**Enums:** {', '.join(t.name for t in enums[:10])}"
                    if len(enums) > 10:
                        result += f" ... (+{len(enums) - 10} more)"
                    result += "\n"

                if structs:
                    result += f"**Structs:** {', '.join(t.name for t in structs[:10])}"
                    if len(structs) > 10:
                        result += f" ... (+{len(structs) - 10} more)"
                    result += "\n"

                if delegates:
                    result += f"**Delegates:** {', '.join(t.name for t in delegates[:10])}"
                    if len(delegates) > 10:
                        result += f" ... (+{len(delegates) - 10} more)"
                    result += "\n"

                result += "\n"

            result += """
**Next Steps:**
- `get_dotnet_types(assembly_path)` - Get detailed type list
- `decompile_dotnet_type(assembly_path, "Namespace.ClassName")` - Decompile a class to C#
- `search_dotnet_types(assembly_path, "pattern")` - Search for types by name
- `decompile_dotnet_assembly(assembly_path)` - Decompile entire assembly
"""
            return result

        except FileNotFoundError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"analyze_dotnet failed: {e}")
            return f"Error analyzing .NET assembly: {e}"

    @app.tool()
    def get_dotnet_types(
        assembly_path: str,
        namespace_filter: str | None = None,
        kind_filter: str | None = None,
        limit: int = 100
    ) -> str:
        """
        List types in a .NET assembly with optional filtering.

        Args:
            assembly_path: Path to .NET assembly
            namespace_filter: Filter by namespace (substring match)
            kind_filter: Filter by type kind (class, interface, enum, struct, delegate)
            limit: Maximum number of types to return

        Returns:
            Formatted list of types with details
        """
        try:
            if not ilspy.is_available():
                return "Error: ILSpyCmd not installed. Run: dotnet tool install -g ilspycmd"

            assembly_info = ilspy.list_types(assembly_path)

            types = assembly_info.types

            # Apply filters
            if namespace_filter:
                types = [t for t in types if namespace_filter.lower() in t.namespace.lower()]

            if kind_filter:
                types = [t for t in types if t.kind.lower() == kind_filter.lower()]

            total = len(types)
            types = types[:limit]

            result = f"**Types: {total} found ({len(types)} shown)**\n\n"

            for t in types:
                kind_icon = {
                    "class": "📦",
                    "interface": "🔌",
                    "enum": "🔢",
                    "struct": "📐",
                    "delegate": "📨"
                }.get(t.kind, "❓")

                result += f"- {kind_icon} **{t.name}** ({t.kind})\n"
                result += f"  - Full Name: `{t.full_name}`\n"
                if t.namespace:
                    result += f"  - Namespace: `{t.namespace}`\n"
                result += "\n"

            if total > limit:
                result += f"\n*Showing {limit} of {total} types. Use filters or increase limit.*"

            return result

        except Exception as e:
            logger.error(f"get_dotnet_types failed: {e}")
            return f"Error: {e}"

    @app.tool()
    def decompile_dotnet_type(
        assembly_path: str,
        type_name: str
    ) -> str:
        """
        Decompile a specific .NET type to C# source code.

        Args:
            assembly_path: Path to .NET assembly
            type_name: Fully qualified type name (e.g., "MyNamespace.MyClass")

        Returns:
            Decompiled C# source code

        Example:
            decompile_dotnet_type("sample.exe", "MalwareNamespace.Downloader")
        """
        try:
            if not ilspy.is_available():
                return "Error: ILSpyCmd not installed. Run: dotnet tool install -g ilspycmd"

            source_code = ilspy.decompile_type(assembly_path, type_name)

            result = f"**Decompiled: {type_name}**\n\n"
            result += "```csharp\n"
            result += source_code
            result += "\n```\n"

            return result

        except ValueError as e:
            # Type not found - suggest similar types
            try:
                matches = ilspy.search_types(assembly_path, type_name.split(".")[-1])
                if matches:
                    suggestions = ", ".join(m.full_name for m in matches[:5])
                    return f"Error: Type '{type_name}' not found.\n\nDid you mean: {suggestions}?"
            except Exception:
                pass
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"decompile_dotnet_type failed: {e}")
            return f"Error: {e}"

    @app.tool()
    def search_dotnet_types(
        assembly_path: str,
        pattern: str,
        limit: int = 50
    ) -> str:
        """
        Search for types matching a pattern in a .NET assembly.

        Args:
            assembly_path: Path to .NET assembly
            pattern: Regex pattern to match type names
            limit: Maximum results to return

        Returns:
            List of matching types

        Example:
            search_dotnet_types("sample.exe", "Crypto|Encrypt|Decrypt")
            search_dotnet_types("sample.exe", "Download")
        """
        try:
            if not ilspy.is_available():
                return "Error: ILSpyCmd not installed. Run: dotnet tool install -g ilspycmd"

            matches = ilspy.search_types(assembly_path, pattern)

            total = len(matches)
            matches = matches[:limit]

            result = f"**Search Results for '{pattern}': {total} matches**\n\n"

            if not matches:
                result += "No types found matching the pattern.\n"
                return result

            for t in matches:
                result += f"- **{t.full_name}** ({t.kind})\n"

            if total > limit:
                result += f"\n*Showing {limit} of {total} matches.*"

            result += "\n\n**To decompile a type:**\n"
            result += f"`decompile_dotnet_type(\"{assembly_path}\", \"TypeName\")`"

            return result

        except ValueError as e:
            return f"Error: Invalid pattern - {e}"
        except Exception as e:
            logger.error(f"search_dotnet_types failed: {e}")
            return f"Error: {e}"

    @app.tool()
    def decompile_dotnet_assembly(
        assembly_path: str,
        force_refresh: bool = False
    ) -> str:
        """
        Decompile entire .NET assembly to C# source files.

        This creates a directory with all decompiled C# source files,
        preserving the namespace/folder structure.

        Args:
            assembly_path: Path to .NET assembly
            force_refresh: Force re-decompilation even if cached

        Returns:
            Path to output directory and summary

        Note:
            For large assemblies, this may take several minutes.
            Results are cached for fast subsequent access.
        """
        try:
            if not ilspy.is_available():
                return "Error: ILSpyCmd not installed. Run: dotnet tool install -g ilspycmd"

            output_dir = ilspy.decompile_assembly(assembly_path, force_refresh=force_refresh)

            # Count decompiled files
            cs_files = list(output_dir.glob("**/*.cs"))

            result = f"""**Assembly Decompiled Successfully**

- **Output Directory:** `{output_dir}`
- **C# Files:** {len(cs_files)}

**Sample Files:**
"""
            for cs_file in cs_files[:10]:
                relative = cs_file.relative_to(output_dir)
                result += f"- `{relative}`\n"

            if len(cs_files) > 10:
                result += f"- ... and {len(cs_files) - 10} more files\n"

            result += """
**Next Steps:**
- Browse the output directory to explore decompiled code
- Use `decompile_dotnet_type()` to view specific types inline
- The decompiled code is cached for fast access
"""
            return result

        except Exception as e:
            logger.error(f"decompile_dotnet_assembly failed: {e}")
            return f"Error: {e}"

    @app.tool()
    def get_dotnet_il(
        assembly_path: str,
        type_name: str | None = None
    ) -> str:
        """
        Get IL (Intermediate Language) disassembly of a .NET assembly or type.

        IL is the low-level bytecode that .NET assemblies are compiled to.
        Useful for understanding obfuscated code or exact implementation details.

        Args:
            assembly_path: Path to .NET assembly
            type_name: Optional type to disassemble (entire assembly if None)

        Returns:
            IL disassembly

        Example:
            get_dotnet_il("sample.exe", "Namespace.ClassName")
        """
        try:
            if not ilspy.is_available():
                return "Error: ILSpyCmd not installed. Run: dotnet tool install -g ilspycmd"

            il_code = ilspy.get_il_code(assembly_path, type_name)

            title = f"IL Disassembly: {type_name or Path(assembly_path).name}"
            result = f"**{title}**\n\n"
            result += "```il\n"

            # Truncate if too long
            if len(il_code) > 50000:
                result += il_code[:50000]
                result += "\n\n... (truncated, IL output too long)\n"
            else:
                result += il_code

            result += "\n```\n"

            return result

        except Exception as e:
            logger.error(f"get_dotnet_il failed: {e}")
            return f"Error: {e}"

    @app.tool()
    def diagnose_dotnet_setup() -> str:
        """
        Check .NET analysis tools installation status.

        Verifies that ILSpyCmd and .NET SDK are properly installed
        and accessible.

        Returns:
            Diagnostic information about .NET tools setup
        """
        try:
            diag = ilspy.diagnose()

            result = "**.NET Analysis Tools Diagnostics**\n\n"

            # ILSpyCmd status
            if diag["ilspycmd_found"]:
                result += "✅ **ILSpyCmd:** Found\n"
                result += f"   - Path: `{diag['ilspycmd_path']}`\n"
                if diag["ilspycmd_version"]:
                    result += f"   - Version: {diag['ilspycmd_version']}\n"
            else:
                result += "❌ **ILSpyCmd:** Not found\n"
                result += "   - Install with: `dotnet tool install -g ilspycmd`\n"

            result += "\n"

            # .NET SDK status
            if diag["dotnet_found"]:
                result += "✅ **.NET SDK:** Found\n"
                result += f"   - Path: `{diag['dotnet_path']}`\n"
                if diag["dotnet_version"]:
                    result += f"   - Version: {diag['dotnet_version']}\n"
            else:
                result += "❌ **.NET SDK:** Not found\n"
                result += "   - Download from: https://dotnet.microsoft.com/download\n"

            result += "\n"

            # Cache info
            result += f"**Cache Directory:** `{diag['cache_dir']}`\n"
            result += f"**Cache Exists:** {'Yes' if diag['cache_dir_exists'] else 'No'}\n"

            result += f"\n**Platform:** {diag['platform']}\n"

            # Overall status
            result += "\n---\n"
            if diag["ilspycmd_found"] and diag["dotnet_found"]:
                result += "✅ **.NET analysis tools are ready!**\n"
            else:
                result += "⚠️ **Setup required.** Install missing components above.\n"

            return result

        except Exception as e:
            logger.error(f"diagnose_dotnet_setup failed: {e}")
            return f"Error: {e}"

    logger.info("Registered 7 .NET analysis tools")
