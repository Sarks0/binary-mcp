#!/usr/bin/env python3
"""
Utility script to view and analyze x64dbg error logs.

Usage:
    python view_errors.py                     # Show recent errors
    python view_errors.py --stats             # Show error statistics
    python view_errors.py --error x64_abc123  # Show specific error
    python view_errors.py --export errors.txt # Export all errors to file
    python view_errors.py --clear             # Clear all errors (with confirmation)
"""

import argparse
import json
import sys
import time
from pathlib import Path

from error_logger import X64DbgErrorLogger


def format_timestamp(timestamp: float) -> str:
    """Format timestamp for display."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def print_error_summary(errors: list[dict]) -> None:
    """Print summary of recent errors."""
    if not errors:
        print("No errors found")
        return

    print(f"\n{'ID':<20} {'Timestamp':<20} {'Operation':<20} {'Error Type':<25}")
    print("=" * 90)

    for error in errors:
        error_id = error["error_id"]
        timestamp = format_timestamp(error["timestamp"])
        operation = error["operation"][:18]
        error_type = error["error_type"][:23]

        print(f"{error_id:<20} {timestamp:<20} {operation:<20} {error_type:<25}")


def print_error_detail(error_logger: X64DbgErrorLogger, error_id: str) -> None:
    """Print detailed information about a specific error."""
    error = error_logger.get_error(error_id)

    if not error:
        print(f"Error not found: {error_id}")
        return

    print("\n" + "=" * 80)
    print(f"ERROR DETAILS: {error_id}")
    print("=" * 80)

    print(f"\nTimestamp:    {format_timestamp(error.timestamp)}")
    print(f"Operation:    {error.operation}")
    print(f"Error Type:   {error.error_type}")
    print(f"Error Message: {error.error_message}")

    if error.http_status:
        print(f"HTTP Status:  {error.http_status}")

    if error.endpoint:
        print(f"Endpoint:     {error.endpoint}")

    if error.duration_ms:
        print(f"Duration:     {error.duration_ms}ms")

    if error.retry_count:
        print(f"Retry Count:  {error.retry_count}")

    if error.context:
        print("\nContext:")
        print(json.dumps(error.context, indent=2))

    if error.api_response:
        print("\nAPI Response:")
        print(json.dumps(error.api_response, indent=2))

    if error.traceback:
        print("\nTraceback:")
        print(error.traceback)

    print("\n" + "=" * 80)


def print_stats(stats: dict) -> None:
    """Print error statistics."""
    if not stats:
        print("No statistics available")
        return

    print("\n" + "=" * 80)
    print("ERROR STATISTICS")
    print("=" * 80)

    total = stats.get("total_errors", 0)
    print(f"\nTotal Errors: {total}")

    if "last_error_timestamp" in stats:
        last_error = format_timestamp(stats["last_error_timestamp"])
        print(f"Last Error:   {last_error}")

    # By operation
    by_operation = stats.get("by_operation", {})
    if by_operation:
        print("\nErrors by Operation:")
        for operation, count in sorted(by_operation.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            print(f"  {operation:<25} {count:>5} ({percentage:>5.1f}%)")

    # By error type
    by_type = stats.get("by_type", {})
    if by_type:
        print("\nErrors by Type:")
        for error_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            print(f"  {error_type:<25} {count:>5} ({percentage:>5.1f}%)")

    # By HTTP status
    by_status = stats.get("by_http_status", {})
    if by_status:
        print("\nErrors by HTTP Status:")
        for status, count in sorted(by_status.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            print(f"  {status:<25} {count:>5} ({percentage:>5.1f}%)")

    print("\n" + "=" * 80)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="View and analyze x64dbg error logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Show 20 most recent errors
  %(prog)s --count 50             Show 50 most recent errors
  %(prog)s --stats                Show error statistics
  %(prog)s --error x64_abc123     Show details for specific error
  %(prog)s --operation step_into  Show all step_into errors
  %(prog)s --export errors.txt    Export all errors to text file
  %(prog)s --clear                Clear all error logs
        """
    )

    parser.add_argument(
        "--count",
        "-n",
        type=int,
        default=20,
        help="Number of recent errors to show (default: 20)"
    )

    parser.add_argument(
        "--stats",
        "-s",
        action="store_true",
        help="Show error statistics"
    )

    parser.add_argument(
        "--error",
        "-e",
        metavar="ERROR_ID",
        help="Show details for specific error ID"
    )

    parser.add_argument(
        "--operation",
        "-o",
        metavar="OPERATION",
        help="Show all errors for a specific operation"
    )

    parser.add_argument(
        "--export",
        "-x",
        metavar="FILE",
        help="Export all errors to text file"
    )

    parser.add_argument(
        "--clear",
        "-c",
        action="store_true",
        help="Clear all error logs (requires confirmation)"
    )

    parser.add_argument(
        "--error-dir",
        metavar="DIR",
        help="Custom error directory (default: ~/.ghidra_mcp_cache/x64dbg_errors/)"
    )

    args = parser.parse_args()

    # Initialize error logger
    error_dir = Path(args.error_dir) if args.error_dir else None
    error_logger = X64DbgErrorLogger(error_dir=error_dir)

    # Handle commands
    if args.clear:
        # Confirm before clearing
        response = input("Are you sure you want to clear all error logs? (yes/no): ")
        if response.lower() == "yes":
            count = error_logger.clear_all_errors()
            print(f"Cleared {count} error records")
        else:
            print("Cancelled")
        return

    if args.export:
        output_file = Path(args.export)
        error_logger.export_errors_log(output_file)
        print(f"Exported errors to {output_file}")
        return

    if args.stats:
        stats = error_logger.get_stats()
        print_stats(stats)
        return

    if args.error:
        print_error_detail(error_logger, args.error)
        return

    if args.operation:
        errors = error_logger.get_errors_by_operation(args.operation)
        if not errors:
            print(f"No errors found for operation: {args.operation}")
            return

        print(f"\nFound {len(errors)} error(s) for operation: {args.operation}\n")

        for error in errors:
            print("-" * 80)
            print(f"Error ID: {error.error_id}")
            print(f"Timestamp: {format_timestamp(error.timestamp)}")
            print(f"Message: {error.error_message}")
            if error.context:
                print(f"Context: {json.dumps(error.context, indent=2)}")

        return

    # Default: show recent errors
    recent_errors = error_logger.get_recent_errors(count=args.count)

    if not recent_errors:
        print("No errors found")
        print(f"\nError directory: {error_logger.error_dir}")
        return

    print(f"\nShowing {len(recent_errors)} most recent errors:")
    print(f"Error directory: {error_logger.error_dir}")
    print_error_summary(recent_errors)

    print(f"\nTo see details: {sys.argv[0]} --error <ERROR_ID>")
    print(f"To see stats:   {sys.argv[0]} --stats")


if __name__ == "__main__":
    main()
