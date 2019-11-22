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
* ``develop`` - is used for development of the next release. **Pull request must be in this branch**
* ``feature/XXX`` - feature branches are used for development of new features before they are merged to ``develop``.

### Prepare development environment
```bash
pip install -r requirements-dev.txt
pytest -munit

# Install `pre-commit` hooks after clone:
pre-commit install
pre-commit run --all-files
```

## Tests
We have two type of test.

### Unit
If you can write unit tests, please do so. How to run them:
```bash
python -mpytest -munit
```

### Integration
For integration test you need have **TEST** local Artifactory instance, which is installed using one of methods:
1. https://github.com/JFrogDev/artifactory-user-plugins-devenv
2. or https://www.jfrog.com/confluence/display/RTF/Installing+Artifactory

Set your Artifactory instances uri\admin-username\admin-password to `tests\test.cfg` file before running the tests

```bash
python -mpytest -mintegration
```
