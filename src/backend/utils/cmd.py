import subprocess
from typing import Dict, Any
import json
import os

def run_cmd_and_parse_output(cmd: list[str], return_dict: bool = True, output_path: str = None) -> Dict[str, Any]|str:
	"""Run the cmd and return the result.

	Input:
	- cmd: a list of strings representing the command to run.

	Output:
	- If the CLI produces valid JSON on stdout and return_dict is True, the parsed Python object is returned.
	- Otherwise, the raw stdout string is returned.
	- If output_path is provided, the output will also be written to the specified file.

	Errors:
	- Raises FileNotFoundError if the command executable is not found in PATH.
	- Raises RuntimeError if the command invocation fails.
	"""
	proc = run_cmd(cmd)

	output = proc.stdout.strip() if proc else ""
	if return_dict:
		# try parsing JSON
		try:
			output = json.loads(output)
		except json.JSONDecodeError as e:
			# If output isn't JSON, fail.
			raise json.JSONDecodeError(f"{cmd} output is not valid JSON", output, 0) from e
		
	# write to output_path if provided
	if output_path:
		directory = os.path.dirname(output_path)
		os.makedirs(directory, exist_ok=True)
		with open(output_path, "w") as f:
			if return_dict:
				json.dump(output, f, indent=4)
			else:
				f.write(output)
	return output

def run_cmd(cmd: list[str]):
    proc = None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError as e:
        raise FileNotFoundError(f"{cmd[0]} executable not found in PATH. Please install {cmd[0]} and ensure it's available.") from e
    except subprocess.CalledProcessError as e:
        print(f"failed to run {cmd} due to error: {e.stderr}")
        raise e
    except Exception as e:
        raise RuntimeError(f"failed to run {cmd} due to error: {e.stderr}") from e
    return proc

