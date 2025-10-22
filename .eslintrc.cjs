module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint', 'import'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:import/recommended',
    'plugin:import/typescript',
    'prettier'
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module'
  },
  settings: {
    'import/extensions': ['.js', '.ts'],
    'import/resolver': {
      typescript: {
        project: ['./tsconfig.json', './tsconfig.cjs.json']
      },
      node: {
        extensions: ['.js', '.ts']
      }
    }
  },
  rules: {
    // Customize any overrides here
  }
};
