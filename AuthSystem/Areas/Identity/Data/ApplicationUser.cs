﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace AuthSystem.Areas.Identity.Data
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        [PersonalData]
        [Column(TypeName ="nvarchar(100)")]
        public string Name { get; set; }
        [PersonalData]
        public DateTimeOffset RegistrationDate { get; set; }
        [PersonalData]
        public DateTimeOffset LastLoginDate { get; set; }
        [PersonalData]
        public bool LockoutStatus { get; set; }

    }
}
