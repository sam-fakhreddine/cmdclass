import subprocess


def aws(profile, *args):
    command = ["aws", "--profile", profile, *args]
    return subprocess.run(command, capture_output=True, text=True)


aws("example", "ec2", "create-tags", "--resources", "fixture-secret")
