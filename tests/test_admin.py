from dohq_artifactory.admin import User


# Добавить чтение url\user\password из файла конфига?
# Протестировать что просто pytest тоже берет нужный конфиг

class TestUser:
    def test_create_user(self):
        repo_name = 'test'
        mail_domain = '@example.com'
        user_reader = User()
        user_reader.name = 'reader_{}'.format(repo_name)
        user_reader.email = 'reader_{}@{}'.format(repo_name, mail_domain)
        user_reader.profileUpdatable = True
        user_reader.groups = '[ "all_users" ]'
