from typing import Dict
import json
import jinja2

def format_size(size_bytes: float) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"

def format_number(num: int) -> str:
    """Format number with thousands separator"""
    return f"{num:,}"

def display_analysis_results(analysis: Dict):
    """Display formatted analysis results"""
    print("\n📊 Analysis Results")
    print("=================")
    
    if analysis.get('layer_analysis'):
        print("\n🔍 Layer Analysis:")
        print(f"  • Total layers: {analysis['layer_analysis']['total_layers']}")
        print(f"  • Total size: {analysis['layer_analysis']['total_size']}")
        
        if analysis.get('unused_files'):
            total_files = analysis['unused_files']['all_files']
            used_files = analysis['unused_files']['used_files']
            unused_size = analysis['unused_files'].get('unused_size', 0)
            
            print(f"  • Files: {format_number(used_files)}/{format_number(total_files)} in use ({format_size(unused_size)} unused)")
    
    if analysis.get('security'):
        print("\n🔒 Security:")
        exposed_ports = analysis['security']['exposed_ports']
        ports_str = f"{len(exposed_ports)} ({', '.join(exposed_ports)})" if exposed_ports else "0"
        
        print(f"  • Exposed ports: {ports_str}")
        print(f"  • Root processes: {len(analysis['security']['root_processes'])}")
        print(f"  • Environment vars: {len(analysis['security']['environment_vars'])}")
    
    if 'optimization_suggestions' in analysis:
        print("\n📊 Optimization Suggestions:")
        print("---------------------------")
        for suggestion in sorted(analysis['optimization_suggestions'], 
                               key=lambda x: x.priority):
            print(f"\n🔹 {suggestion.category} (Priority: {suggestion.priority})")
            print(f"   {suggestion.description}")
            print(f"   Potential savings: {_format_size(suggestion.potential_savings)}")