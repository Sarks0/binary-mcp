"""
Output formatting utilities for analysis results.
"""



def format_function_list(functions: list[dict], limit: int = 50) -> str:
    """
    Format a list of functions for display.

    Args:
        functions: List of function dicts
        limit: Maximum number to display

    Returns:
        Formatted string
    """
    result = f"**Functions: {len(functions)} total**\n\n"

    for func in functions[:limit]:
        name = func.get('name', 'Unknown')
        addr = func.get('address', 'Unknown')
        sig = func.get('signature', 'Unknown')

        result += f"- **{name}** @ `{addr}`\n"
        result += f"  {sig}\n\n"

    if len(functions) > limit:
        result += f"\n*Showing {limit} of {len(functions)} functions*\n"

    return result


def format_iocs(iocs: dict[str, list[str]]) -> str:
    """
    Format IOCs for display.

    Args:
        iocs: Dictionary of IOC types to lists of values

    Returns:
        Formatted string
    """
    result = "**Indicators of Compromise**\n\n"

    for ioc_type, values in sorted(iocs.items()):
        if values:
            formatted_type = ioc_type.replace('_', ' ').title()
            result += f"### {formatted_type}\n\n"
            for value in sorted(values):
                result += f"- `{value}`\n"
            result += "\n"

    return result


def format_api_calls(api_calls: list[dict]) -> str:
    """
    Format API calls for display.

    Args:
        api_calls: List of API call dicts

    Returns:
        Formatted string
    """
    result = "**API Calls**\n\n"

    # Group by category
    by_category = {}
    for api in api_calls:
        cat = api.get('category', 'unknown')
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(api)

    for category, apis in sorted(by_category.items()):
        result += f"### {category.upper()}\n\n"
        for api in apis:
            result += f"- **{api.get('name')}** [{api.get('severity')}]\n"
            result += f"  {api.get('description')}\n\n"

    return result


def format_memory_map(memory_blocks: list[dict]) -> str:
    """
    Format memory map for display.

    Args:
        memory_blocks: List of memory block dicts

    Returns:
        Formatted string
    """
    result = "**Memory Map**\n\n"

    for block in memory_blocks:
        name = block.get('name', 'Unknown')
        start = block.get('start', '?')
        end = block.get('end', '?')
        size = block.get('size', 0)
        perms = ""

        if block.get('read'):
            perms += "R"
        if block.get('write'):
            perms += "W"
        if block.get('execute'):
            perms += "X"

        result += f"- **{name}** [{perms}]\n"
        result += f"  {start} - {end} ({size} bytes)\n\n"

    return result


def truncate_string(s: str, max_length: int = 100) -> str:
    """
    Truncate a string with ellipsis.

    Args:
        s: String to truncate
        max_length: Maximum length

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def format_bytes(num_bytes: int) -> str:
    """
    Format byte count as human-readable string.

    Args:
        num_bytes: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"
