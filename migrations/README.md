# Database Migrations for 304Tracker

This directory contains the migration scripts for the 304Tracker application. Migrations are essential for managing changes to the database schema over time, ensuring that the database structure is in sync with the application's models.

## Setting Up Migrations

To set up the migrations for the 304Tracker project, follow these steps:

1. **Install Dependencies**: Ensure that you have the required dependencies installed. You can do this by running:

   ```
   pip install -r requirements.txt
   ```

2. **Initialize Migrations**: If you haven't already initialized the migrations, you can do so by running:

   ```
   flask db init
   ```

3. **Create a Migration**: Whenever you make changes to the models, create a new migration script with:

   ```
   flask db migrate -m "Description of changes"
   ```

4. **Apply Migrations**: To apply the migrations to the database, run:

   ```
   flask db upgrade
   ```

## Migration Scripts

Migration scripts will be generated in this directory. Each script contains the necessary operations to update the database schema. It is important to review these scripts before applying them to ensure they accurately reflect the intended changes.

## Rollback Migrations

If you need to revert to a previous migration, you can use the following command:

```
flask db downgrade
```

This will roll back the last migration applied.

## Best Practices

- Always back up your database before applying migrations.
- Test migrations in a development environment before applying them to production.
- Keep migration messages clear and descriptive for future reference.

For more detailed information on Flask-Migrate, refer to the official documentation: [Flask-Migrate Documentation](https://flask-migrate.readthedocs.io/en/latest/)