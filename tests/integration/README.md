# dpapi-ng Integration Environment

This contains a Vagrantfile and Ansible playbook that can be used to setup an AD environment to test sansldap with more complex scenarios.
The plan is to expand this environment setup to test out edge case scenarios that cannot be done through CI.

To set up the environment run the following:

```bash
ansible-galaxy collection install -r requirements.yml

vagrant up

ansible-playbook main.yml -vv
```

Before running `main.yml`, download the `artifact` zip from the GitHub Actions workflow to test.
This zip should be placed in the same directory as the playbook as `artifact.zip`.
