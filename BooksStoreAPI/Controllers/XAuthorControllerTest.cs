using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BooksStoreAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace BooksStoreAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class XAuthorControllerTest : ControllerBase
    {
        [HttpGet]
        public IEnumerable<Author> Get()
        {
            using (var context = new BookStoresDBContext())
            {
                //get all authors
                return context.Authors.ToList();

                //get author by id 
                //return context.Author.Where(auth => auth.AuthorId == 1).ToList();

                //Create
                //Author author = new Author();
                //author.FirstName = "John";
                //author.LastName = "Smith";
                //context.Author.Add(author);
                //context.SaveChanges();
                //return context.Author.Where(auth => auth.FirstName == "John").ToList();

                //Update
                //Author author = context.Author.Where(auth => auth.FirstName == "John").FirstOrDefault();
                //author.Phone = "777-777-7777";
                //context.SaveChanges();
                //return context.Author.Where(auth => auth.FirstName == "John").ToList();

                //Delete
                //Author author = context.Author.Where(auth => auth.FirstName == "John").FirstOrDefault();
                //context.Author.Remove(author);
                //context.SaveChanges();
                //return context.Author.Where(auth => auth.FirstName == "John").ToList();
            }
        }
    }
}
