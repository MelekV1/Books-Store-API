using System;
using System.Collections.Generic;

// Code scaffolded by EF Core assumes nullable reference types (NRTs) are not used or disabled.
// If you have enabled NRTs for your project, then un-comment the following line:
// #nullable disable

namespace BooksStoreAPI.Models
{
    public partial class Publisher
    {
        public Publisher()
        {
            Book = new HashSet<Book>();
            User = new HashSet<User>();
        }

        public int PubId { get; set; }
        public string PublisherName { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Country { get; set; }

        public virtual ICollection<Book> Book { get; set; }
        public virtual ICollection<User> User { get; set; }
    }
}
