from api.models.vxdf import VXDFModel
import json
import sys

output_file_path = "generated_vxdf_schema.json"

try:
    # Ensure all forward references are resolved and models are finalized.
    # Pydantic v2's model_rebuild() is generally good for this.
    VXDFModel.model_rebuild()

    schema = VXDFModel.model_json_schema()
    
    with open(output_file_path, 'w') as f:
        json.dump(schema, f, indent=2)
    
    print(f"Schema successfully written to {output_file_path}", file=sys.stdout)

except Exception as e:
    print(f"Script Error: {e}", file=sys.stderr)
    sys.exit(1) 