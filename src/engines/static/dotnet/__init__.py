"""
.NET static analysis engine using ILSpyCmd.

Provides decompilation of .NET assemblies to C# source code,
type enumeration, and method extraction.
"""

from src.engines.static.dotnet.ilspy_runner import ILSpyRunner

__all__ = ["ILSpyRunner"]
