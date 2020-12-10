using System;
using NUnit.Framework;
using Microsoft.AspNet.Identity;


namespace engineer_3_labs
{
    [TestFixture]
    public class Tests1
    {
        PasswordHasher ph = new PasswordHasher();

        [Test]
        public void CheckHashIsGenated()
        {
            // Arrange
            string pw = "qqweqqwe";

             // Act 
            string hash = ph.HashPassword(pw);

            // Assert
            Assert.AreNotEqual(pw, hash);
        }


        [Test]
        public void CheckHashSuccessfulVerification()
        {
            // Arrange
            string pw = "qqweqqwe";
            PasswordVerificationResult result;

            // Act 
            string hash = ph.HashPassword(pw);
            result = ph.VerifyHashedPassword(hash, pw);

            // Assert
            Assert.AreEqual(result, PasswordVerificationResult.Success);
        }

        [Test]
        public void CheckHashUnsuccessfulVerification()
        {
            // Arrange
            string pw1 = "qqweqqwe";
            string pw2 = "Qqwe1123";

            PasswordVerificationResult result;

            // Act 
            string hash = ph.HashPassword(pw1);
            result = ph.VerifyHashedPassword(hash, pw2);

            // Assert
            Assert.AreEqual(result, PasswordVerificationResult.Failed);
        }

        [Test]
        public void CheckHashWithEmptyString()
        {
            // Arrange
            string pw = "";
            PasswordVerificationResult result;

            // Act 
            string hash = ph.HashPassword(pw);
            result = ph.VerifyHashedPassword(hash, pw);

            // Assert
            Assert.AreEqual(result, PasswordVerificationResult.Success);
        }

        [Test]
        public void CheckHashWithSpecialSymbols()
        {
            // Arrange
            string pw = "!@#$%^&*()";
            PasswordVerificationResult result;

            // Act 
            string hash = ph.HashPassword(pw);
            result = ph.VerifyHashedPassword(hash, pw);

            // Assert
            Assert.AreEqual(result, PasswordVerificationResult.Success);
        }

        [Test]
        public void CheckHashWithNull()
        {
            // Arrange
            string pw = null;

            // Act 
            try {
                string hash = ph.HashPassword(pw);
                Assert.Fail();
            } catch (ArgumentNullException e) {
                // Assert
                Assert.Pass();
            }
        }
    }
}
