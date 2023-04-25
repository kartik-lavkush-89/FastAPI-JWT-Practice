def userEntity(item) -> dict:
    """
    Converts the user data returned from the database to a dictionary.

    Args:
        item: A dictionary containing the user's data.

    Returns:
        A dictionary with the user's data.

    """
    return {
        "username": item["username"],
        "email": item["email"],
        "phone": item["phone"],
    }




''' Entity for employee task '''

def employeeEntity(item) -> dict:
    return {
        "username": item["username"],
        "email": item["email"],
        "phone": item["phone"]
    }

def employeesEntity(entity) -> list:
    return [employeeEntity(item) for item in entity]