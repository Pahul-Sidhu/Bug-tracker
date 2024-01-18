using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Bug_tracker.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Bug_tracker.Controllers;


public class ChoiceController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly UserManager<IdentityUser> _userManager;

    private readonly SignInManager<IdentityUser> _signInManager;

    public ChoiceController(ILogger<HomeController> logger, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
    {
        _logger = logger;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpGet]
    public IActionResult Index(string email)
    {
        ViewData["Email"] = email;
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    public IActionResult Index(string email, string selectedRole)
    {
        // Retrieve the user by email
        var user = _userManager.FindByEmailAsync(email).Result;

        if (user != null && !string.IsNullOrEmpty(selectedRole))
        {
            var roles = _userManager.GetRolesAsync(user).Result;
            if (roles.Count > 0)
            {
                // Redirect to the desired page after sign-in
                return RedirectToAction("Index", "Home");
            }

            // Add the user to the selected role
            _userManager.AddToRoleAsync(user, selectedRole).Wait();

            // Sign in the user
            _signInManager.SignInAsync(user, isPersistent: false).Wait();

            // Redirect to the desired page after sign-in
            return RedirectToAction("Index", "Home");
        }

        // Handle error or redirect to an error page
        return RedirectToAction("Error");
    }


}