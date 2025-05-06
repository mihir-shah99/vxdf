#!/usr/bin/env python3
"""
Test script for the VXDF frontend integration.
This script uses Playwright to automate browser testing of the frontend.

Prerequisites:
- Python 3.7+
- pip install playwright
- playwright install
"""
import os
import sys
import time
import asyncio
from playwright.async_api import async_playwright, Error as PlaywrightError


# Configuration
FRONTEND_URL = "http://localhost:3000"
TEST_DATA_DIR = "test-data"


class Colors:
    """Terminal colors for test output."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    BLUE = "\033[94m"


def print_section(title):
    """Print a section title."""
    print(f"\n{Colors.BLUE}{'=' * 80}")
    print(f" {title}")
    print(f"{'=' * 80}{Colors.RESET}\n")


def print_test(name, passed):
    """Print a test result."""
    status = f"{Colors.GREEN}PASSED{Colors.RESET}" if passed else f"{Colors.RED}FAILED{Colors.RESET}"
    print(f"  [TEST] {name}: {status}")


def print_warning(message):
    """Print a warning message."""
    print(f"  {Colors.YELLOW}[WARNING] {message}{Colors.RESET}")


def print_info(message):
    """Print an info message."""
    print(f"  [INFO] {message}")


async def test_frontend_loads(page):
    """Test if the frontend loads correctly."""
    print_section("Testing Frontend Loading")
    
    try:
        await page.goto(FRONTEND_URL)
        await page.wait_for_selector("main", timeout=5000)
        
        # Check for header and sidebar
        header_exists = await page.is_visible("header")
        sidebar_exists = await page.is_visible("nav", strict=False)
        
        print_test("Page loaded", True)
        print_test("Header exists", header_exists)
        print_test("Sidebar exists", sidebar_exists)
        
        # Take a screenshot
        screenshot_path = os.path.join(TEST_DATA_DIR, "frontend-load.png")
        await page.screenshot(path=screenshot_path)
        print_info(f"Screenshot saved to {screenshot_path}")
        
        return header_exists and sidebar_exists
        
    except PlaywrightError as e:
        print_test("Page loaded", False)
        print_warning(f"Error: {str(e)}")
        return False


async def test_dashboard_component(page):
    """Test the dashboard component."""
    print_section("Testing Dashboard Component")
    
    try:
        await page.goto(FRONTEND_URL)
        await page.wait_for_selector("main", timeout=5000)
        
        # Check if we're on the dashboard page by default
        dashboard_visible = await page.is_visible("h2:text('Validation Dashboard')")
        print_test("Dashboard is visible by default", dashboard_visible)
        
        if not dashboard_visible:
            print_warning("Dashboard not visible, attempting to navigate to it")
            # Try to click the dashboard link in the sidebar
            await page.click("text=Dashboard")
            await page.wait_for_selector("h2:text('Validation Dashboard')")
            dashboard_visible = await page.is_visible("h2:text('Validation Dashboard')")
            print_test("Dashboard navigation works", dashboard_visible)
        
        # Check for stat cards
        stat_cards = await page.query_selector_all(".bg-white.rounded-lg.shadow.p-5")
        print_test("Dashboard shows statistics cards", len(stat_cards) > 0)
        print_info(f"Found {len(stat_cards)} statistics cards")
        
        # Check for vulnerabilities table
        table_exists = await page.is_visible("table")
        print_test("Vulnerabilities table exists", table_exists)
        
        if table_exists:
            # Check if table has content
            table_rows = await page.query_selector_all("table tbody tr")
            print_info(f"Found {len(table_rows)} rows in the vulnerabilities table")
        
        # Take a screenshot
        screenshot_path = os.path.join(TEST_DATA_DIR, "dashboard.png")
        await page.screenshot(path=screenshot_path)
        print_info(f"Screenshot saved to {screenshot_path}")
        
        return dashboard_visible
        
    except PlaywrightError as e:
        print_test("Dashboard component test", False)
        print_warning(f"Error: {str(e)}")
        return False


async def test_file_upload_component(page):
    """Test the file upload component."""
    print_section("Testing File Upload Component")
    
    sarif_file = os.path.join(TEST_DATA_DIR, "sample-sarif.json")
    
    if not os.path.exists(sarif_file):
        print_warning(f"Test file not found: {sarif_file}")
        return False
    
    try:
        await page.goto(FRONTEND_URL)
        await page.wait_for_selector("main", timeout=5000)
        
        # Navigate to upload page
        await page.click("text=Upload")
        await page.wait_for_selector("h2:text('Upload Security Scans')")
        
        upload_page_visible = await page.is_visible("h2:text('Upload Security Scans')")
        print_test("Upload page navigation works", upload_page_visible)
        
        if not upload_page_visible:
            return False
        
        # Check for drag-drop area
        drag_drop_area = await page.query_selector(".border-dashed")
        print_test("Drag and drop area exists", drag_drop_area is not None)
        
        # Check for file input and attempt upload
        file_input = await page.query_selector("input[type=file]")
        print_test("File input exists", file_input is not None)
        
        if file_input is not None:
            # Upload the file
            await file_input.set_input_files(sarif_file)
            print_info(f"Uploaded file: {sarif_file}")
            
            # Check if file appears in the list
            await page.wait_for_selector("li:has-text('sample-sarif.json')")
            file_in_list = await page.is_visible("li:has-text('sample-sarif.json')")
            print_test("File appears in the list after upload", file_in_list)
            
            # Take a screenshot of the file list
            screenshot_path = os.path.join(TEST_DATA_DIR, "file-upload-list.png")
            await page.screenshot(path=screenshot_path)
            print_info(f"Screenshot saved to {screenshot_path}")
            
            # Check for parser type selection
            parser_type_select = await page.query_selector("#parser-type")
            print_test("Parser type selection exists", parser_type_select is not None)
            
            # Check the Start Validation button
            start_button = await page.query_selector("button:text('Start Validation')")
            print_test("Start Validation button exists", start_button is not None)
            
            if start_button is not None:
                # Submit the file for validation
                print_info("Clicking Start Validation button")
                await start_button.click()
                
                try:
                    # Wait for the validation process
                    await page.wait_for_selector("text=Validating...", timeout=2000)
                    print_test("Validation process started", True)
                    
                    # Wait for validation to complete and redirect to dashboard
                    await page.wait_for_selector("h2:text('Validation Dashboard')", timeout=20000)
                    redirected_to_dashboard = await page.is_visible("h2:text('Validation Dashboard')")
                    print_test("Redirected to dashboard after validation", redirected_to_dashboard)
                    
                    # Check if vulnerabilities table has content after upload
                    await page.wait_for_selector("table tbody tr", timeout=5000)
                    table_rows = await page.query_selector_all("table tbody tr")
                    print_info(f"Found {len(table_rows)} rows in the vulnerabilities table after upload")
                    print_test("Vulnerabilities displayed after upload", len(table_rows) > 0)
                    
                    # Take a screenshot of the results
                    screenshot_path = os.path.join(TEST_DATA_DIR, "validation-results.png")
                    await page.screenshot(path=screenshot_path)
                    print_info(f"Screenshot saved to {screenshot_path}")
                    
                    return redirected_to_dashboard and len(table_rows) > 0
                    
                except PlaywrightError as e:
                    print_test("Validation process", False)
                    print_warning(f"Error during validation: {str(e)}")
                    
                    # Check if there's an error message
                    error_visible = await page.is_visible(".bg-red-100")
                    if error_visible:
                        error_text = await page.text_content(".bg-red-100")
                        print_warning(f"Error message: {error_text}")
                    
                    return False
            
        return drag_drop_area is not None and file_input is not None
        
    except PlaywrightError as e:
        print_test("File upload component test", False)
        print_warning(f"Error: {str(e)}")
        return False


async def test_error_handling(page):
    """Test error handling in the frontend."""
    print_section("Testing Error Handling")
    
    try:
        await page.goto(FRONTEND_URL)
        await page.wait_for_selector("main", timeout=5000)
        
        # Navigate to upload page
        await page.click("text=Upload")
        await page.wait_for_selector("h2:text('Upload Security Scans')")
        
        # Create an empty file for testing
        empty_file = os.path.join(TEST_DATA_DIR, "empty.json")
        with open(empty_file, "w") as f:
            f.write("{}")
        
        print_info(f"Created empty test file: {empty_file}")
        
        # Upload the empty file
        file_input = await page.query_selector("input[type=file]")
        await file_input.set_input_files(empty_file)
        
        # Check if file appears in the list
        await page.wait_for_selector("li:has-text('empty.json')")
        
        # Click the Start Validation button
        start_button = await page.query_selector("button:text('Start Validation')")
        if start_button is not None:
            await start_button.click()
            
            # Wait for potential error message
            try:
                await page.wait_for_selector(".bg-red-100", timeout=10000)
                error_visible = await page.is_visible(".bg-red-100")
                print_test("Error message displayed for invalid file", error_visible)
                
                if error_visible:
                    error_text = await page.text_content(".bg-red-100")
                    print_info(f"Error message: {error_text}")
                
                # Take a screenshot of the error
                screenshot_path = os.path.join(TEST_DATA_DIR, "error-handling.png")
                await page.screenshot(path=screenshot_path)
                print_info(f"Screenshot saved to {screenshot_path}")
                
                # Test error dismissal
                close_button = await page.query_selector(".bg-red-100 button")
                if close_button:
                    await close_button.click()
                    
                    # Check if error is dismissed
                    await page.wait_for_timeout(1000)  # Wait for animation
                    error_dismissed = not await page.is_visible(".bg-red-100")
                    print_test("Error message can be dismissed", error_dismissed)
                    
                return error_visible
                
            except PlaywrightError:
                print_test("Error message displayed for invalid file", False)
                print_warning("No error message was displayed for the invalid file")
                return False
        
        return False
        
    except PlaywrightError as e:
        print_test("Error handling test", False)
        print_warning(f"Error: {str(e)}")
        return False
    finally:
        # Clean up the empty file
        if os.path.exists(empty_file):
            os.unlink(empty_file)


async def run_tests():
    """Run all frontend tests."""
    print_section("VXDF Frontend Testing")
    
    # Make sure test data directory exists
    if not os.path.exists(TEST_DATA_DIR):
        os.makedirs(TEST_DATA_DIR)
        print_warning(f"Created test data directory: {TEST_DATA_DIR}")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        # Run all tests
        tests_passed = 0
        tests_failed = 0
        
        test_funcs = [
            test_frontend_loads,
            test_dashboard_component,
            test_file_upload_component,
            test_error_handling
        ]
        
        for test_func in test_funcs:
            if await test_func(page):
                tests_passed += 1
            else:
                tests_failed += 1
        
        # Print summary
        print_section("Test Summary")
        print(f"Tests passed: {Colors.GREEN}{tests_passed}{Colors.RESET}")
        print(f"Tests failed: {Colors.RED}{tests_failed}{Colors.RESET}")
        print(f"Total tests:  {tests_passed + tests_failed}")
        
        await browser.close()
        
        return tests_failed > 0


def main():
    """Main function."""
    try:
        result = asyncio.run(run_tests())
        sys.exit(1 if result else 0)
    except Exception as e:
        print(f"{Colors.RED}ERROR: {str(e)}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main() 