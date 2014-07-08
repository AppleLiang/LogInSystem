using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Security.Cryptography;

namespace LogInSystem.Controllers
{
    public class UserController : Controller
    {
        public const int SALT_BYTE_SIZE = 24;
        public const int HASH_BYTE_SIZE = 24;
        public const int PBKDF2_ITERATIONS = 1000;
        //
        // GET: /User/

        public ActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public ActionResult LogIn()
        {
            return View();
        }

        [HttpPost]
        public ActionResult LogIn(Models.UserModel user)
        {
            if (ModelState.IsValid)
            {
                if (IsValid(user.Email, user.Password))
                {
                    FormsAuthentication.SetAuthCookie(user.Email, false);
                    return RedirectToAction("Index", "User");
                }
                else
                {
                    ModelState.AddModelError("", "Login data is incorrect");
                }
            }
            return View(user); 
        }

        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Registration(Models.UserModel user)
        {
            if(ModelState.IsValid)
            {
                using(var db = new AzureMainDbEntities())
                {
                    var sysUser = db.User.Create();

                    // create salt and password hash
                    RNGCryptoServiceProvider csprng = new RNGCryptoServiceProvider();
                    byte[] salt = new byte[SALT_BYTE_SIZE];
                    csprng.GetBytes(salt);

                    byte[] hash = PBKDF2(user.Password, salt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE);

                    sysUser.Email = user.Email;
                    sysUser.Password = Convert.ToBase64String(hash);
                    sysUser.PasswordSalt = Convert.ToBase64String(salt);
                    sysUser.UserId = Guid.NewGuid();

                    db.User.Add(sysUser);
                    db.SaveChanges();

                    return RedirectToAction("Index", "Home");
                }
            }
            return View();
        }

        public ActionResult LogOut()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Home");
        }
        private bool IsValid (string email, string password)
        {
            bool isValid = false;

            using (var db = new AzureMainDbEntities())
            {
                var user = db.User.FirstOrDefault(a => a.Email == email);

                if(user != null)
                {
                    byte[] salt = Convert.FromBase64String(user.PasswordSalt);

                    byte[] correctHash = Convert.FromBase64String(user.Password);

                    byte[] testHash = PBKDF2(password, salt, PBKDF2_ITERATIONS, correctHash.Length);

                    if(SlowEquals(correctHash, testHash))
                    {
                        isValid = true;
                    }
                }
            }

            return isValid;
        }

        // compute the hash of a password using PBKDF2-SHA1
        private byte[] PBKDF2(string password, byte[] salt, int iterations, int outputBytes) 
        {
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt);
            pbkdf2.IterationCount = iterations;
            return pbkdf2.GetBytes(outputBytes);
        }

        // Compare two byte arrays
        private bool SlowEquals(byte[] a, byte [] b) 
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for(int i = 0; i < a.Length && i < b.Length; i++) 
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }
    }
}
