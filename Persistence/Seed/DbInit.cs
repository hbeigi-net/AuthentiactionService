namespace Persistence.Seed;

using System.Runtime.InteropServices;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.Data;

public static class DbInit {
  public static async Task Seed(
    IServiceProvider services
  ){
    
      using var initScope = services.CreateScope();
      var dbContext = initScope.ServiceProvider.GetRequiredService<AuthDbContext>();
      await dbContext.Database.EnsureCreatedAsync();
      var roleManager = initScope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();

      if(!roleManager.Roles.Any()) {
        await roleManager.CreateAsync(new ApplicationRole("root"));
        await roleManager.CreateAsync(new ApplicationRole("admin"));
        await roleManager.CreateAsync(new ApplicationRole("user"));
      }

      Console.WriteLine("Seed Success.");
  }
}