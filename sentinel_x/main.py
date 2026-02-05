"""
Main entry point for SENTINEL-X
"""

import argparse
import sys
from pathlib import Path
from .core.agent import AutonomousAgent
from .utils.report_generator import ReportGenerator


def main():
    """Main function for SENTINEL-X CLI"""
    parser = argparse.ArgumentParser(
        description="SENTINEL-X: Autonomous AI Incident Commander",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinel-x --log-file /path/to/logs.txt --output report.txt
  sentinel-x -f logs.json --format json -o report.json
  sentinel-x -f security.log --confidence 0.90
        """
    )
    
    parser.add_argument(
        '-f', '--log-file',
        type=str,
        help='Path to log file to analyze'
    )
    
    parser.add_argument(
        '--log-format',
        type=str,
        choices=['generic', 'json', 'syslog', 'csv'],
        default='generic',
        help='Log file format (default: generic)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file path for the report (default: stdout)'
    )
    
    parser.add_argument(
        '--format',
        type=str,
        choices=['text', 'json', 'summary'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '-c', '--confidence',
        type=float,
        default=0.85,
        help='Confidence threshold for investigation termination (default: 0.85)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='SENTINEL-X 0.1.0'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.log_file:
        parser.print_help()
        sys.exit(1)
    
    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Error: Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Create agent and run investigation
        agent = AutonomousAgent(confidence_threshold=args.confidence)
        report = agent.investigate(log_file_path=str(log_path))
        
        # Generate report in requested format
        if args.format == 'json':
            output = ReportGenerator.generate_json_report(report)
        elif args.format == 'summary':
            output = ReportGenerator.generate_summary(report)
        else:
            output = ReportGenerator.generate_text_report(report)
        
        # Write output
        if not report.is_incident:
            print("\nNo incident detected. No report file created.")
            return

        if args.output:
            output_path = Path(args.output)
            # Create parent directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)
            # Write with UTF-8 encoding
            output_path.write_text(output, encoding='utf-8')
            
            print("\n" + "=" * 80)
            print(f"Report successfully saved to: {output_path.absolute()}")
            print("=" * 80)
            print("\nReport Summary:")
            print(ReportGenerator.generate_summary(report))
        else:
            print("\n" + output)
        
    except Exception as e:
        print(f"Error during investigation: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
