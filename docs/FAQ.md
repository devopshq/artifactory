# FAQ

## Upload to pypi-repositories
Original issue: [30](https://github.com/devopshq/artifactory/issues/30)

We have two way:
1. Upload to pypi repository to specific path: `pypi.repo/projectname/0.3.34193/projectname-0.3.34193-py3-none-any.whl`, where `projectname` is pypi package name, `0.3.34193` pypi version. After ~ 1 min package will be available in pypi-index
2. Upload to pypi and set pypi-specific properties: `pypi.summary, pypi.version, pypi.name, pypi.normalized.name`. See example [in issue](https://github.com/devopshq/artifactory/issues/30#issuecomment-418430571)
