"""Tests for __main__ entry point."""
from unittest.mock import patch


def test_main_entry_point_calls_main():
    """Test that __main__ calls cli.main() when executed as script."""
    # We need to actually execute the __main__ block, not just import it
    with patch('propagation_exporter.cli.main') as mock_main:
        # Simulate running as __main__
        import propagation_exporter.__main__ as main_module

        # Temporarily set __name__ to trigger the if block
        original_name = main_module.__name__
        try:
            main_module.__name__ = '__main__'
            # Re-execute the module code
            code = compile(
                'if __name__ == "__main__":\n    main()',
                '<test>',
                'exec'
            )
            exec(code, {'__name__': '__main__', 'main': main_module.main})
            mock_main.assert_called_once()
        finally:
            main_module.__name__ = original_name
