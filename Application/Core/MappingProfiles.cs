using System;
using Application.Auth.DTOs;
using Application.User.DTOs;
using AutoMapper;
using Domain.Entities;

namespace Application.Core;

public class MappingProfiles: Profile
{
  public MappingProfiles()
  {
    CreateMap<ApplicationUser, UserInfoDTO>()
      .ForMember(
        dest => dest.Roles,
        opt => opt.MapFrom(src => src.UserRoles.Select(role => role.Role.Name).ToList())
      );

    CreateMap<UpdateUserDto, ApplicationUser>();
    CreateMap<ApplicationUser, UserInfoDto>();
  }
}
