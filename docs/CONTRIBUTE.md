# Table of Contents
- [Development](#development)
- [Tests](#tests)

We will be grateful to see you in the ranks of the contributors! We have [some issue](https://github.com/devopshq/artifactory/issues).

## Development
Development takes place on GitHub, where the git-flow branch structure is used:

* ``master`` - contains the latest released code.
* ``develop`` - is used for development of the next release. **Pull request must be in this branch**
* ``feature/XXX`` - feature branches are used for development of new features before they are merged to ``develop``.

## Tests
We have 2 type of test

### Unit
You can write unit-test. Please, do it. How to run unit-tests:
```bash
python -mpytest -munit
```

### Integration
For integration test you need have local Artifactory instance, which is installed useing one of methods:
1. https://github.com/JFrogDev/artifactory-user-plugins-devenv
2. or https://www.jfrog.com/confluence/display/RTF/Installing+Artifactory

Set you Artifactory instances uri\admin-username\admin-password to `tests\test.cfg` file before run test

```bash
python -mpytest -mintegration
```
