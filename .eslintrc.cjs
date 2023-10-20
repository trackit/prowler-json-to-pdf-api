module.exports = {
    env: {
        node: true,
        browser: true,
        jest: true,
        es6: true,
    },
    parser: "@typescript-eslint/parser",
    plugins: ["unused-imports", "simple-import-sort", "no-secrets"],
    extends: [
        "prettier",
        "eslint:recommended",
        "plugin:@typescript-eslint/recommended",
        "plugin:prettier/recommended",
        "plugin:import/errors",
        "plugin:import/warnings",
        "plugin:import/typescript",
        "plugin:jsonc/base",
    ],
    parserOptions: {
        ecmaVersion: 2018,
        sourceType: "module",
        ecmaFeatures: {
            jsx: true,
        },
    },
    rules: {
        "no-case-declarations": "off",
        "@typescript-eslint/no-unused-vars": "off",
        "no-secrets/no-secrets": "error",
    },
};
