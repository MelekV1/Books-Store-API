using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BooksStoreAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace BooksStoreAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthorController : ControllerBase
    {
        [HttpGet]
        public IEnumerable<Author>Get()
        {
            using (var context = new BookStoresDBContext())
            {
                //get all authors
                return context.Author.ToList();
            }
        }
    }
}
