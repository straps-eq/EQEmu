def patch_template(template_path, opcodes_path, output_path):
    try:
        with open(opcodes_path, 'r') as f:
            opcodes = [line.strip() for line in f if line.strip()]
        
        with open(template_path, 'r') as f:
            content = f.read()

        for index, value in enumerate(opcodes):
            placeholder = f"{{{{{index}}}}}"
            content = content.replace(placeholder, value)

        with open(output_path, 'w') as f:
            f.write(content)
        
        print(f"Successfully transformed: {output_path}")

    except FileNotFoundError as e:
        print(f"Error: File Not Found - {e}")
    except Exception as e:
        print(f"Error: Exception - {e}")

if __name__ == "__main__":
    patch_template(
        template_path='opcode.template', 
        opcodes_path='opcodes.csv', 
        output_path='patch_TOB.conf'
    )