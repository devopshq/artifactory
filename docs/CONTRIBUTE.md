# Table of Contents

<!-- toc -->

- [Development](#development)
  * [Prepare development environment](#prepare-development-environment)
- [Tests](#tests)
  * [Unit](#unit)
  * [Integration](#integration)

<!-- tocstop -->

We will be grateful to see you in the ranks of the contributors! We have [some issues](https://github.com/devopshq/artifactory/issues).

## Development
Development takes place on GitHub, where the git-flow branch structure is used:

* ``master`` - contains the latest released code.
* ``feature/XXX`` - feature branches are used for development of new features before they are merged to ``master``.

### Prepare development environment
It is recommended to use Unix systems. You can use free Oracle Virtualbox and Ubuntu.  
Setup script for Ubuntu system (python version might be 3.7+):
```bash
python3.7 -m pip install tox
python3.7 -m pip install .[tests]
python3.7 -m pytest -munit

# install ruby (required for pre-commit)
sudo apt install ruby

# run pre-commit
python3.7 -m pre_commit install
python3.7 -m pre_commit run --all-files
```

If you use another system procedure might be different.  
General script:
```bash
python -m pip install tox
python -m pip install .[tests]
python -m pytest -munit

# Install `pre-commit` hooks after clone:
pre-commit install
pre-commit run --all-files
```

## Tests
Command snippet to run tests via tox
```bash
# Run unit tests
tox
# Run integration tests
tox -- -mintegration
# Run Unit and Integration tests
tox -- ""
```

### Unit
If you can write unit tests, please do so. How to run them:
```bash
python -m pytest -munit
```

### Integration
We also have some integration test. But you have to prepare your environment a little before you can run these tests.

0. Get [Trial License Key](https://jfrog.com/artifactory/free-trial/) from JFrog
1. Run Artifactory Pro (only Pro support full REST API) inside docker by command: 
```bash
docker run --name artifactory-pro -d -p 8081:8081 -p8082:8082 docker.bintray.io/jfrog/artifactory-pro
```
2. Open http://localhost:8081 and wait until it'll be ready
3. Login with `admin \ password` and complete initialize steps:
   1. Change password to `P@ssw0rd`. It's important to use exactly this password, we hardcoded it in [test.cfg](../tests/test.cfg)
   2. Change token to real one in [test.cfg](../tests/test.cfg).
   [Token authentation](https://www.jfrog.com/confluence/display/JFROG/Access+Tokens)
   method is for some special components, like
   [Projects](https://www.jfrog.com/confluence/display/JFROG/Artifactory+REST+API#ArtifactoryRESTAPI-PROJECTS)
   3. Install trial license
   
That all, try to run integration tests!
```bash
# Run with current python
python -mpytest -mintegration

# Run through all versions with we do support
tox -- -mintegration
```

Some useful command with docker:
```bash
# Stop artifactory, but save License and user\password
docker stop artifactory-pro

# Start stopped Artifactory. 
docker start artifactory-pro

# Remove installed Artifactory. You'll have to comlete initialize steps again!
docker rm artifactory-pro
```



