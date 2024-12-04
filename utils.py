def format_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}PB"

def display_analysis_results(analysis: dict):
    """Display formatted analysis results"""
    print("\n📊 Analysis Results")
    print("=================")
    
    if analysis.get('layer_analysis'):
        print("\n🔍 Layer Analysis:")
        print(f"  • Total layers: {analysis['layer_analysis']['total_layers']}")
        print(f"  • Total size: {analysis['layer_analysis']['total_size']}")
        if analysis.get('unused_files') and analysis['unused_files'].get('unused_size'):
            unused_size = analysis['unused_files']['unused_size']
            print(f"  • Unused size: {format_size(unused_size)}")
        
    if analysis.get('unused_files'):
        print("\n📁 File Usage:")
        total_size = analysis['unused_files'].get('total_size', 0)
        unused_size = analysis['unused_files'].get('unused_size', 0)
        print(f"  • Total files: {analysis['unused_files']['all_files']} ({format_size(total_size)})")
        print(f"  • Used files: {analysis['unused_files']['used_files']}")
        print(f"  • Unused files: {analysis['unused_files']['total_unused']} ({format_size(unused_size)})")
        
    if analysis.get('security'):
        print("\n🔒 Security Scan:")
        print(f"  • Exposed ports: {len(analysis['security']['exposed_ports'])}")
        print(f"  • Root processes: {len(analysis['security']['root_processes'])}")
        print(f"  • Environment variables: {len(analysis['security']['environment_vars'])}") 