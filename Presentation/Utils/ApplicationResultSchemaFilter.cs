
using Application.Core;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Presentation.Utils;

public class ApplicationResultSchemaFilter : ISchemaFilter
{
    public void Apply(OpenApiSchema schema, SchemaFilterContext context)
    {
        if (context.Type.IsGenericType && context.Type.GetGenericTypeDefinition() == typeof(ApplicationResult<>))
        {
            var valueType = context.Type.GetGenericArguments()[0];
            var valueTypeName = valueType.Name;

            // Clear existing properties to avoid conflicts
            schema.Properties.Clear();

            // Add the standard ApplicationResult properties
            schema.Properties["statusCode"] = new OpenApiSchema { Type = "integer", Format = "int32" };
            schema.Properties["value"] = new OpenApiSchema { Reference = new OpenApiReference { Type = ReferenceType.Schema, Id = valueTypeName } };
            schema.Properties["errorMessage"] = new OpenApiSchema { Type = "string", Nullable = true };
            schema.Properties["isSuccess"] = new OpenApiSchema { Type = "boolean" };
            schema.Properties["redirectUrl"] = new OpenApiSchema { Type = "string", Nullable = true };
            schema.Properties["errors"] = new OpenApiSchema 
            { 
                Type = "object",
                AdditionalProperties = new OpenApiSchema { Type = "array", Items = new OpenApiSchema { Type = "string" } },
                Nullable = true 
            };

            // Set required properties
            schema.Required = new HashSet<string> { "isSuccess" };
        }
    }
}