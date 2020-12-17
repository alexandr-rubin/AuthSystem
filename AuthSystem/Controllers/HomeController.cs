using AuthSystem.Data;
using AuthSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Areas.Identity.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using AuthSystem.Areas.Identity.Pages.Account;

namespace AuthSystem.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public HomeController(ILogger<HomeController> logger, UserManager<ApplicationUser> userManager, AuthDbContext db, SignInManager<ApplicationUser> signInManager)
        {
            _logger = logger;
            _userManager = userManager;
            _db = db;
            _signInManager = signInManager;
        }
        [HttpGet]
        public IActionResult Index()
        {
            return View(_userManager.Users.ToList());
        }

        [HttpPost]
        public async Task<IActionResult> UserManagement(IFormCollection formCollection, string submitButton)
        {
            var ids = formCollection["userId"].ToString().Split(new char[] { ',' });
            foreach (var item in ids)
            {
                var user = _db.Users.Find(item);
                if (user == null)
                    return RedirectToAction("Index");
                else if (submitButton == "Delete")
                {
                    await _userManager.UpdateSecurityStampAsync(user);
                    _db.Users.Remove(user);
                    _db.SaveChanges();
                }
                else if (submitButton == "Block")
                {
                    await _userManager.UpdateSecurityStampAsync(user);
                    user.LockoutStatus = true;
                    await _userManager.SetLockoutEnabledAsync(user, true);
                    await _userManager.SetLockoutEndDateAsync(user, DateTime.Today.AddYears(100));
                }
                else if (submitButton == "Unblock")
                {
                    user.LockoutStatus = false;
                    await _userManager.SetLockoutEnabledAsync(user, false);
                }
            }
            if (ids.Contains(_userManager.GetUserId(User)) && submitButton != "Unblock")
                await _signInManager.SignOutAsync();
            return RedirectToAction("Index");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
