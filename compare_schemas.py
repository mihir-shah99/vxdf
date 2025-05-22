import json
import sys
import re

def clean_json_string(json_str):
    # Rule 1: Fix invalid escapes for square brackets.
    # Step 1.1: Globally convert '\\\\[' to '[' and '\\\\]' to ']'
    # This will fix array delimiters like required: \\\\[\"foo\"\\\\] -> required: [\"foo\"].
    # It will also change patterns from \"pattern\": \"^\\\\[a\\\\]\" to \"pattern\": \"^[a]\".
    json_str = json_str.replace("\\\\[", "[")
    json_str = json_str.replace("\\\\]", "]")

    # Step 1.2: For "pattern" fields, escape '[' and ']' to become '\\\\\\[' and '\\\\\\]' (literal \\\\ & [ in file).
    def escape_brackets_in_pattern_value(match):
        # match.group(0) is the whole match, e.g., "\"pattern\": \"^[a-z]$\"
        # match.group(1) is (\"pattern\":\\s*\")\n
        # match.group(2) is the pattern value itself, e.g., ^[a-z]$\n
        # match.group(3) is (\")\n
        prefix = match.group(1)
        pattern_value = match.group(2)
        suffix = match.group(3)
        
        # To write literal \"\\\\\\[\" (meaning \\\\ then [) to file, Python string must be \"\\\\\\\\\\\\\"
        pattern_value = pattern_value.replace("[", "\\\\\\\\\\\\") # Change [ to literal \\\\\[ in file
        pattern_value = pattern_value.replace("]", "\\\\\\\\\\\\") # Change ] to literal \\\\\] in file
        return f"{prefix}{pattern_value}{suffix}"

    # Regex to find "\"pattern\": \"<value>\""
    # It captures three groups: (prefix before value)(value)(suffix after value)
    json_str = re.sub(r'(\"pattern\":\s*\")([^\"]*)(\")', escape_brackets_in_pattern_value, json_str)
    
    # Rule 2: Fix \\# in $refs, e.g., "\"\\\\#/$defs/" to "\"#/$defs/"
    json_str = json_str.replace("\"\\\\#/$defs/", "\"#/$defs/")

    # Rule 3: Fix \\\\` (backslash-backtick) to ` (literal backtick) in descriptions.
    json_str = json_str.replace("\\\\`", "`")

    return json_str

def compare_schemas():
    generated_schema_path = "generated_vxdf_schema.json"
    normative_schema_path = "docs/normative-schema.json"

    try:
        with open(generated_schema_path, 'r') as f:
            generated_schema_str = f.read()
        generated_json = json.loads(generated_schema_str)
        print(f"Successfully loaded generated schema: {generated_schema_path}")
    except Exception as e:
        print(f"Error loading generated schema '{generated_schema_path}': {e}", file=sys.stderr)
        return

    normative_json_to_compare = None
    try:
        with open(normative_schema_path, 'r') as f:
            normative_schema_str_original = f.read()
        
        print("Attempting to clean the normative schema string...", file=sys.stdout)
        cleaned_normative_schema_str = clean_json_string(normative_schema_str_original)
        
        cleaned_normative_schema_path = "docs/normative-schema-cleaned-attempt.json"
        with open(cleaned_normative_schema_path, 'w') as f_cleaned:
            f_cleaned.write(cleaned_normative_schema_str)
        print(f"Cleaned normative schema attempt saved to: {cleaned_normative_schema_path}", file=sys.stdout)

        try:
            normative_json_to_compare = json.loads(cleaned_normative_schema_str)
            print(f"Successfully loaded CLEANED normative schema from string.", file=sys.stdout)
        except json.JSONDecodeError as e_cleaned:
            print(f"Error loading CLEANED normative schema from string: {e_cleaned}", file=sys.stderr)
            print("Automatic cleaning failed. Please check 'normative-schema-cleaned-attempt.json' and the errors.", file=sys.stderr)
            try:
                print("Attempting to parse original normative schema again to show its specific error...", file=sys.stdout)
                json.loads(normative_schema_str_original)
            except json.JSONDecodeError as e_original:
                 print(f"Original normative schema also fails to parse: {e_original}", file=sys.stderr)
            return

    except Exception as e:
        print(f"Error reading or processing normative schema '{normative_schema_path}': {e}", file=sys.stderr)
        return

    if normative_json_to_compare is None:
        print("Could not load normative schema for comparison.", file=sys.stderr)
        return

    # Perform comparison
    if generated_json == normative_json_to_compare:
        print("\nComparison Result: SCHEMAS ARE IDENTICAL.")
    else:
        print("\nComparison Result: SCHEMAS ARE DIFFERENT.")
        if isinstance(generated_json, dict) and isinstance(normative_json_to_compare, dict):
            generated_keys = set(generated_json.keys())
            normative_keys = set(normative_json_to_compare.keys())
            
            if generated_keys == normative_keys:
                print("Top-level keys are the same. Differences are likely in nested values or definitions.")
                if "$defs" in generated_json and "$defs" in normative_json_to_compare:
                    gen_defs_keys = set(generated_json.get("$defs", {}).keys())
                    norm_defs_keys = set(normative_json_to_compare.get("$defs", {}).keys())
                    if gen_defs_keys == norm_defs_keys:
                         print("Keys within $defs are also the same. Differences are deeper.")
                    else:
                        print(f"Keys only in generated $defs: {sorted(list(gen_defs_keys - norm_defs_keys))}")
                        print(f"Keys only in normative $defs: {sorted(list(norm_defs_keys - gen_defs_keys))}")
                
                for k in sorted(list(generated_keys)):
                    if generated_json.get(k) != normative_json_to_compare.get(k):
                        print(f"First differing top-level key found: '{k}'.")
                        gen_val = generated_json.get(k)
                        norm_val = normative_json_to_compare.get(k)
                        print(f"  Type in Generated: {type(gen_val)}, Type in Normative: {type(norm_val)}")
                        if isinstance(gen_val, str) and isinstance(norm_val, str):
                            if len(gen_val) > 200 or len(norm_val) > 200:
                                print(f"    Generated (first 200 chars): {gen_val[:200]}...")
                                print(f"    Normative (first 200 chars): {norm_val[:200]}...")
                            else:
                                print(f"    Generated: {gen_val}")
                                print(f"    Normative: {norm_val}")
                        elif isinstance(gen_val, list) and isinstance(norm_val, list):
                            print(f"    Generated list length: {len(gen_val)}, Normative list length: {len(norm_val)}")
                        elif isinstance(gen_val, dict) and isinstance(norm_val, dict):
                            print(f"    (Field '{k}' is a dict, differences are within)")

                        break 
            else:
                print(f"Keys only in generated schema: {sorted(list(generated_keys - normative_keys))}")
                print(f"Keys only in normative schema: {sorted(list(normative_keys - generated_keys))}")
        print("You may want to use a dedicated JSON diff tool to inspect 'generated_vxdf_schema.json' and 'docs/normative-schema-cleaned-attempt.json'.")

if __name__ == "__main__":
    compare_schemas() 