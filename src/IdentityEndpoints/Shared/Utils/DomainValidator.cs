using FluentValidation;

namespace IdentityEndpoints.Utils;

public static class DomainValidator
{
    public static void Validate<T, TV>(T instance) where T : class where TV : IValidator<T>, new()
    {
        var validator = new TV();
        var validation = validator.Validate(instance);
        if (!validation.IsValid)
        {
            throw new ValidationException("One or more validation checks failed",
                 validation.Errors);
        }
    }
}