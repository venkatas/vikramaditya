#!/usr/bin/env python3
"""
Demo script showing HAR-based VAPT using Vikramaditya Enhanced Platform
Demonstrates complete workflow from HAR file to comprehensive security assessment
"""

import os
import json
from datetime import datetime
from har_analyzer import HARAnalyzer
from har_vapt_engine import HARVAPTEngine


def demo_har_workflow(har_file: str):
    """Demonstrate complete HAR-based VAPT workflow"""

    print("🚀 Vikramaditya Enhanced - HAR-Based VAPT Demo")
    print("=" * 60)
    print(f"📁 Processing HAR file: {har_file}")
    print()

    # Step 1: Analyze HAR file
    print("🔍 Step 1: Analyzing HAR file...")
    analyzer = HARAnalyzer(har_file)
    analysis = analyzer.analyze()

    if 'error' in analysis:
        print(f"❌ Analysis failed: {analysis['error']}")
        return

    # Display analysis summary
    config = analysis['config']
    print(f"✅ Analysis complete!")
    print(f"   Target: {config['target_domain']}")
    print(f"   Endpoints: {config['total_endpoints']}")
    print(f"   High-value targets: {config['high_value_endpoints']}")
    print(f"   Technology: {', '.join(config['technology_stack'])}")
    print()

    # Step 2: Save analysis results
    print("💾 Step 2: Saving analysis results...")
    analysis_file = har_file.replace('.har', '_analysis.json')
    analyzer.save_analysis(analysis_file, analysis)

    # Step 3: Run comprehensive VAPT
    print("🧪 Step 3: Running comprehensive VAPT...")
    engine = HARVAPTEngine(analysis)
    results = engine.run_comprehensive_scan()

    # Step 4: Save VAPT results
    print("📊 Step 4: Saving VAPT results...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"vapt_results_{config['target_domain']}_{timestamp}.json"

    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    # Display results summary
    vuln_summary = results['vulnerability_summary']
    print(f"✅ VAPT completed!")
    print(f"   Total vulnerabilities: {vuln_summary['total_vulnerabilities']}")
    print(f"   Critical: {vuln_summary['critical']}")
    print(f"   High: {vuln_summary['high']}")
    print(f"   Medium: {vuln_summary['medium']}")
    print(f"   Results saved to: {results_file}")

    return results_file


def main():
    """Demo with existing HAR files"""

    # Demo with available HAR files
    demo_files = [
        "/Users/venkatasatish/Documents/test.har",
        "/Users/venkatasatish/Documents/test2.har",
        "/Users/venkatasatish/Documents/test3.har",
        "/Users/venkatasatish/Documents/test4.har"
    ]

    print("🎯 Vikramaditya Enhanced VAPT Platform Demo")
    print("=" * 70)
    print("This demo shows the complete HAR-based VAPT workflow:")
    print("1. HAR file analysis and endpoint extraction")
    print("2. Session data and authentication token extraction")
    print("3. Attack surface mapping")
    print("4. Comprehensive vulnerability testing")
    print("5. Results generation and reporting")
    print("=" * 70)
    print()

    # Process each available HAR file
    results_files = []

    for har_file in demo_files:
        if os.path.isfile(har_file):
            print(f"\n📋 Processing: {os.path.basename(har_file)}")
            print("-" * 50)

            try:
                result_file = demo_har_workflow(har_file)
                if result_file:
                    results_files.append(result_file)
                print("✅ Processing completed successfully!")

            except Exception as e:
                print(f"❌ Error processing {har_file}: {e}")

            print("-" * 50)

    # Summary
    print(f"\n🎉 Demo completed!")
    print(f"📊 Processed {len([f for f in demo_files if os.path.isfile(f)])} HAR files")
    print(f"📁 Generated {len(results_files)} result files:")

    for result_file in results_files:
        print(f"   • {result_file}")

    print("\n📋 Next steps:")
    print("   1. Review vulnerability findings in the JSON results")
    print("   2. Run remediation tests after fixes")
    print("   3. Generate HTML reports using reporter.py")
    print("   4. Implement recommended security controls")

    return results_files


if __name__ == "__main__":
    main()