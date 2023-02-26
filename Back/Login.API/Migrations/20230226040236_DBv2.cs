using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Login.API.Migrations
{
    /// <inheritdoc />
    public partial class DBv2 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "112c9aa5-9a73-4f83-8958-26ef113b6368", "2", "User", "User" },
                    { "758ebdda-1dfa-4a19-ab2b-77d0267a2825", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "112c9aa5-9a73-4f83-8958-26ef113b6368");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "758ebdda-1dfa-4a19-ab2b-77d0267a2825");
        }
    }
}
