using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Bug_tracker.Data;
using Humanizer;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

// builder.Services.AddIdentity<XUser, XRole>(options => options.Stores.MaxLengthForKeys = 128)
//     .AddEntityFrameworkStores<ApplicationDbContext>()
//     .AddDefaultTokenProviders()
//     .AddRoles<XRole>();

builder.Services.AddControllersWithViews();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var roles = new[] { "Admin", "Manager", "Developer", "Submitter" };

    foreach (var role in roles)
    {
        if (!roleManager.RoleExistsAsync(role).Result)
        {
            roleManager.CreateAsync(new IdentityRole(role)).Wait();
        }
    }
}

using (var scope = app.Services.CreateScope())
{
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    var demo_user_emails = new[] {"demo@admin.com", "demo@manager.com", "demo@developer.com", "demo@submitter.com"};
    var demo_user_password = "Password1!";

    foreach (var email in demo_user_emails)
    {
        var user = new IdentityUser { UserName = email, Email = email };
        user.EmailConfirmed = true;
        var roles = new[] { "Admin", "Manager", "Developer", "Submitter" };
        if (userManager.FindByEmailAsync(email).Result == null)
        {
            userManager.CreateAsync(user, demo_user_password).Wait();
            var role = roles.Where(r => email.Contains(r.ToLower())).ToList();
            userManager.AddToRoleAsync(user, role[0]).Wait();
        }
    }
    
}

app.Run();
