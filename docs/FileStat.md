# FileStat
You can get hash (`md5`, `sha1`), create and change date:

```python
from artifactory import ArtifactoryPath
path = ArtifactoryPath(
    "http://repo.jfrog.org/artifactory/distributions/org/apache/tomcat/apache-tomcat-7.0.11.tar.gz")

# Get FileStat
stat = ArtifactoryPath.stat(path)
print(stat)
print(stat.md5)
print(stat.sha1)
print(stat.ctime)
print(stat.is_dir)
print(stat.size)
```

