using Domain.Common;
using Domain.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Persistence.Data;
public class AuthDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure RefreshToken entity
        builder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(rt => rt.Id);
            entity.Property(rt => rt.Token).IsRequired();
            entity.Property(rt => rt.ExpiryDate).IsRequired();
            entity.Property(rt => rt.CreatedAt).IsRequired();
            
            // Relationship with ApplicationUser
            entity.HasOne(rt => rt.User)
                  .WithMany(u => u.ReferashTokens)
                  .HasForeignKey(rt => rt.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Configure ApplicationUser
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(u => u.FirstName).HasMaxLength(50);
            entity.Property(u => u.LastName).HasMaxLength(50);
        });

        // Configure ApplicationUserRole relationships
        builder.Entity<ApplicationUserRole>(entity =>
        {
            // Configure the User navigation property to use the existing UserId foreign key
            entity.HasOne(ur => ur.User)
                  .WithMany(u => u.UserRoles)
                  .HasForeignKey(ur => ur.UserId)
                  .IsRequired();

            // Configure the Role navigation property to use the existing RoleId foreign key
            entity.HasOne(ur => ur.Role)
                  .WithMany(r => r.RoleUsers)
                  .HasForeignKey(ur => ur.RoleId)
                  .IsRequired();
        });

        // Configure ApplicationRoleClaim relationships
        builder.Entity<ApplicationRoleClaim>(entity =>
        {
            // Configure the Role navigation property to use the existing RoleId foreign key
            entity.HasOne(rc => rc.Role)
                  .WithMany(r => r.RoleClaims)
                  .HasForeignKey(rc => rc.RoleId)
                  .IsRequired();
        });
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        // Set audit fields before saving
        var entries = ChangeTracker.Entries<IAuditableEntity>()
            .Where(e => e.State == EntityState.Added || e.State == EntityState.Modified);

        foreach (var entry in entries)
        {
            if (entry.State == EntityState.Added)
            {
                entry.Entity.CreatedAt = DateTime.UtcNow;
                entry.Entity.CreatedBy = "system"; // TODO: Get from current user
            }
            else
            {
                entry.Entity.UpdatedAt = DateTime.UtcNow;
                entry.Entity.UpdatedBy = "system"; // TODO: Get from current user
            }
        }

        return base.SaveChangesAsync(cancellationToken);
    }
}