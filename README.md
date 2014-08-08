# Python interface library for Jfrog Artifactory #

[![Build Status](https://travis-ci.org/Parallels/artifactory.svg?branch=develop)](https://travis-ci.org/Parallels/artifactory)

This module is intended to serve as a logical descendant of [pathlib](https://docs.python.org/3/library/pathlib.html), a Python 3 module for object-oriented path manipulations. As such, it implements everything as closely as possible to the origin with few exceptions, such as stat().

# Usage Examples #

## Walking Directory Tree ##

Getting directory listing:

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath("http://repo.jfrog.org/artifactory/gradle-ivy-local")
for p in path:
    print p
```

Find all .gz files in current dir, recursively:

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath("http://repo.jfrog.org/artifactory/distributions/org/")

for p in path.glob("**/*.gz"):
    print p
```

## Downloading Artifacts ##

Download artifact to a local filesystem:

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath("http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz")
    
with path.open() as fd:
    with open("tomcat.tar.gz", "wb") as out:
        out.write(fd.read())
```

## Uploading Artifacts ##

Deploy a regular file ```myapp-1.0.tar.gz```

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath("http://my-artifactory/artifactory/libs-snapshot-local/myapp/1.0")
path.mkdir()

path.deploy_file('./myapp-1.0.tar.gz')
```
Deploy a debian package ```myapp-1.0.deb```

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath("http://my-artifactory/artifactory/ubuntu-local/pool")
path.deploy_deb('./myapp-1.0.deb', distribution='trusty', component='main', architecture='amd64')
```
