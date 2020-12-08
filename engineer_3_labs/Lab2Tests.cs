using NUnit.Framework;
using Microsoft.AspNet.Identity;


namespace IIG.CoSFE.DatabaseUtils
{
    [TestFixture]
    public class Tests2
    {

        private const string Server = @"localhost,1433";
        private const string Database = @"IIG.CoSWE.AuthDB";
        private const bool IsTrusted = false;
        private const string Login = @"sa";
        private const string Password = @"Qqwe1123";
        private const int ConnectionTimeout = 75;

        private static AuthDatabaseUtils DB = new AuthDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);

        private static PasswordHasher ph = new PasswordHasher();

        [SetUp]
        public void Setup()
        {
            // Clear database before test session running
            DB.ExecSql("DELETE FROM dbo.Credentials");
        }


        [Test]
        public void CheckAddCredentialsToDB()
        {
            // Arrange
            string password = ph.HashPassword("password");
            string login = "treshch1";

            // Act
            bool res = DB.AddCredentials(login, password);

            // Assert
            Assert.IsTrue(DB.CheckCredentials(login, password));
        }

        [Test]
        public void CheckUpdatePasswordInDB()
        {
            // Arrange
            string password = ph.HashPassword("somehash1");
            string changedPassword = ph.HashPassword("somehash2");
            string login = "treshch2";

            // Act
            DB.AddCredentials(login, password);
            DB.UpdateCredentials(login, password, login, changedPassword);

            // Assert
            Assert.IsFalse(DB.CheckCredentials(login, password));
            Assert.IsTrue(DB.CheckCredentials(login, changedPassword));
        }

        [Test]
        public void CheckUpdateLoginInDB()
        {
            // Arrange
            string password = ph.HashPassword("somehash");
            string login = "treshch3";
            string changedLogin = "treshch4";


            // Act
            DB.AddCredentials(login, password);
            DB.UpdateCredentials(login, password, changedLogin, password);

            // Assert
            Assert.IsFalse(DB.CheckCredentials(login, password));
            Assert.IsTrue(DB.CheckCredentials(changedLogin, password));
        }

        [Test]
        public void CheckUpdateLoginAndPasswordInDB()
        {
            // Arrange
            string password = ph.HashPassword("somehash1");
            string changedPassword = ph.HashPassword("somehash2");
            string login = "treshch5";
            string changedLogin = "treshch6";


            // Act
            DB.AddCredentials(login, password);
            DB.UpdateCredentials(login, password, changedLogin, changedPassword);

            // Assert
            Assert.IsFalse(DB.CheckCredentials(login, password));
            Assert.IsTrue(DB.CheckCredentials(changedLogin, changedPassword));
        }

        [Test]
        public void CheckCreationTheSameLogin()
        {
            // Arrange
            string password = ph.HashPassword("somehash1");
            string password2 = ph.HashPassword("somehash2");
            string login = "treshch7";

            // Act
            DB.AddCredentials(login, password);
            DB.AddCredentials(login, password2);

            // Assert
            Assert.IsTrue(DB.CheckCredentials(login, password));
            Assert.IsFalse(DB.CheckCredentials(login, password2));
        }

        [Test]
        public void CheckCreationWithSmallPassword()
        {
            // Arrange
            string password = "123456789012345678901234567890123456789012345678901234567890123"; // 63 chars
            string login = "treshch8";

            // Act
            DB.AddCredentials(login, password);

            // Assert
            Assert.IsFalse(DB.CheckCredentials(login, password));
        }

        [Test]
        public void CheckCreationWithNullPassword()
        {
            // Arrange
            string password = null;
            string login = "treshch8";

            // Act
            DB.AddCredentials(login, password);

            // Assert
            Assert.IsFalse(DB.CheckCredentials(login, password));
        }

        [Test]
        public void CheckCreationWithBlankLogin()
        {
            // Arrange
            string password = ph.HashPassword("somehash1");
            string login = "";

            // Act
            DB.AddCredentials(login, password);

            // Assert
            Assert.IsFalse(DB.CheckCredentials(login, password));
        }

        [Test]
        public void CheckCredentialsDeleting()
        {
            // Arrange
            string password = ph.HashPassword("somehash1");
            string login = "treshch9";

            // Act
            DB.AddCredentials(login, password);
            DB.DeleteCredentials(login, password);

            // Assert
            Assert.IsFalse(DB.CheckCredentials(login, password));
        }
    }
}