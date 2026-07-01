#!/usr/bin/env python3

import base64
import asyncio
import os
import sys
import cv2
import numpy as np
import qrcode
import struct
import flet as ft
import webbrowser
from io import BytesIO

# Import exact core wallet backend logic from your script
from semaj_cli_wallet import (
    b58_to_signer,
    encrypt,
    process_to_keypair,
    transfer_sol,
    transfer_spl_token,
    get_solana_balance,
    list_spl_balances,
    stake_sol,
    unstake_sol,
    list_stakes
)

# Global variables for layout dimensions and styling

async def async_fetch_stake_accounts(sender_pubkey):
    """Runs your existing backend list_stakes function safely in a background thread."""
    try:
        # Re-uses your exact list_stakes() function without duplicating any parsing math
        return await asyncio.to_thread(list_stakes, sender_pubkey)
    except Exception as err:
        print(f"[ERROR] Failed calling backend list_stakes function: {err}")
        return []
async def main(page: ft.Page):
    page.title = "Semaj's Solana Wallet"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 20
    page.scroll = ft.ScrollMode.HIDDEN

    if page.platform in [ft.PagePlatform.MACOS, ft.PagePlatform.WINDOWS, ft.PagePlatform.LINUX]:
        page.window.width = 450
        page.window.height = 800
        page.window.resizable = False
    else:
        page.window.width = None
        page.window.height = None

    state = {
        "scanned_qr_content": "",
        "wallet_qr_passcode": "",
        "wallet_pubkey": None,
        "sol_balance": 0.0,
        "token_list": [],
        "cap": None,
        "active_scan_target": None,
        "transfer_to_address": None,
        "signer_qr_str": "",
        "signer_scan_done": asyncio.Event(),
        "is_scanning": False,
        "is_processing": False
    }

    qr_decoder = cv2.QRCodeDetector()

    def trigger_scan_success_beep():
        """Fires an audible alert frequency notice safely across operating systems without external packages."""
        try:
            if sys.platform == "win32":
                import winsound
                winsound.Beep(2000, 150)  # 2000Hz frequency tone for 150ms
            else:
                sys.stdout.write('\a')
                sys.stdout.flush()
        except Exception as sound_err:
            print(f"[AUDIO WARN] Audio subsystem notice skipped: {sound_err}")

    async def unified_camera_worker():
        print("\n" + "="*50)
        print("[CAMERA DEBUG] SYSTEM INITIATING SAFE SCANNER STREAM TASK...")
        print("="*50)
        frame_counter = 0

        while state["is_scanning"] and state["cap"] and state["cap"].isOpened():
            if not state["is_scanning"] or state["is_processing"]:
                break
            try:
                success, frame = await asyncio.to_thread(state["cap"].read)
                if not success:
                    await asyncio.sleep(0.01)
                    continue
                frame_counter += 1
            except Exception as hardware_read_error:
                print(f"[HW LOG ERR] Failed to read frame from lens bus: {hardware_read_error}")
                await asyncio.sleep(0.02)
                continue

            try:
                h, w, _ = frame.shape
                min_dim = min(h, w)
                start_x = (w - min_dim) // 2
                start_y = (h - min_dim) // 2
                square_frame = frame[start_y:start_y+min_dim, start_x:start_x+min_dim]
                small_frame = cv2.resize(square_frame, (320, 320))

                _, encoded_buffer = cv2.imencode(".jpg", small_frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
                base64_raw = base64.b64encode(encoded_buffer).decode("utf-8")
                camera_viewfinder.src = f"data:image/jpeg;base64,{base64_raw}"
                page.update()
            except Exception as stream_layout_error:
                print(f"[STREAM ERR] Layout paint skipped: {stream_layout_error}")
                pass

            try:
                gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                data, bbox, _ = qr_decoder.detectAndDecode(gray_frame)

                if data and not state["is_processing"]:
                    clean_data = data.strip()
                    if clean_data:
                        state["is_processing"] = True
                        trigger_scan_success_beep()  # Confirmation tone alert

                        if state["active_scan_target"] == "login":
                            state["scanned_qr_content"] = clean_data
                            qr_status_label.value = f"Successfully Loaded\nWallet: {clean_data[:3]}..."
                            qr_status_label.size = 48
                            qr_status_label.color = ft.Colors.GREEN
                            qr_status_label.update()
                            await stop_active_scanner()
                            break
                        elif state["active_scan_target"] == "signer":
                            state["signer_qr_str"] = clean_data
                            await stop_active_scanner()
                            if page.dialog:
                                page.dialog.open = False
                            page.update()
                            state["active_scan_target"] = ""
                            state["signer_scan_done"].set()
                            break
                        elif state["active_scan_target"] == "transfer" and state["transfer_to_address"]:
                            state["transfer_to_address"].value = clean_data
                            await stop_active_scanner()
                            if page.dialog:
                                page.dialog.open = False
                            page.update()
                            break
            except Exception as decoder_matrix_error:
                if frame_counter % 30 == 0:
                    print(f"[DECODER WARN] Scanner check error: {decoder_matrix_error}")
                pass
            await asyncio.sleep(0.03)
        print("[CAMERA DEBUG] Thread worker tracking loop shut down cleanly.")

    async def toggle_login_scanner(e):
        if state["is_processing"]:
            print("[WARN BLOCK] Duplicate click discarded. Scanner pipeline is currently busy.")
            return

        if not state["is_scanning"]:
            state["is_processing"] = True
            print("[CAMERA DEBUG] Button click captured. Engaging input lock and initializing lens...")
            state["cap"] = await asyncio.to_thread(cv2.VideoCapture, 0, cv2.CAP_AVFOUNDATION)

            if state["cap"] and state["cap"].isOpened():
                state["cap"].set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                state["cap"].set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                state["is_scanning"] = True

                scan_ctrl_btn.content = ft.Text("Stop Camera Feed", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD)
                scan_ctrl_btn.bgcolor = ft.Colors.RED_ACCENT_400
                state["active_scan_target"] = "login"

                camera_status_overlay_text.value = "STEP 1: INITIAL PASS IDENTITY SCANNER ACTIVE"
                camera_status_overlay_text.color = ft.Colors.BLUE_400
                camera_container.content = ft.Stack([camera_viewfinder, camera_status_container])
                page.update()

                state["is_processing"] = False
                asyncio.create_task(unified_camera_worker())
            else:
                state["cap"] = None
                state["is_processing"] = False
                qr_status_label.value = "Failed to access local camera hardware."
                page.update()
        else:
            state["is_processing"] = True
            await stop_active_scanner()
    async def stop_active_scanner():
        print("[CAMERA DEBUG] Executing hardware resource release sequence...")
        state["is_scanning"] = False
        await asyncio.sleep(0.05)
        try:
            if state["cap"] is not None:
                state["cap"].release()
        except Exception as hardware_release_err:
            print(f"[HW LOG CRIT] Crash caught during capture release pass: {hardware_release_err}")
        finally:
            state["cap"] = None
            state["is_processing"] = False

        if state["active_scan_target"] == "login":
            scan_ctrl_btn.content = ft.Text("Start QR Scanner", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD)
            scan_ctrl_btn.bgcolor = ft.Colors.BLUE_700
            camera_container.content = qr_status_label
        page.update()

    async def refresh_wallet_data():
        try:
            state["sol_balance"] = await asyncio.to_thread(get_solana_balance, state["wallet_pubkey"])
            state["token_list"] = await asyncio.to_thread(list_spl_balances, state["wallet_pubkey"])
        except Exception as err:
            await show_popup_message("Network Error", f"Sync failed: {str(err)}")

    async def handle_wallet_unlock(e):
        if state["is_scanning"]:
            await stop_active_scanner()
        if not state["scanned_qr_content"]:
            await show_popup_message("Security Lock", "Please scan your encrypted key QR first.")
            return

        state["wallet_qr_passcode"] = password_input.value.strip()
        if not state["wallet_qr_passcode"]:
            await show_popup_message("Input Error", "Passcode entry field cannot be empty.")
            return

        formatted_input = state["scanned_qr_content"][:-1] + f',"{state["wallet_qr_passcode"]}")'
        the_b58 = process_to_keypair(formatted_input, "LEDGER")
        if not the_b58:
            await show_popup_message("Decryption Failed", "Invalid Passcode configuration.")
            return

        try:
            state["wallet_pubkey"] = b58_to_signer(the_b58).pubkey()
            await refresh_wallet_data()
            await build_main_ui()
        except Exception as err:
            await show_popup_message("Initialization Error", f"Parsing error: {str(err)}")

    async def open_staking_dashboard(e):
        """Displays the top-level native staking dashboard view overlay."""
        sol_bal = "0.0"
        for tok in state["token_list"]:
            if isinstance(tok, dict) and tok.get("name") == "SOL":
                sol_bal = tok.get("balance", "0.0")

        dashboard_view = ft.Column(spacing=10, tight=True, width=420)

        dashboard_view.controls.append(
            ft.Container(
                content=ft.Row([
                    ft.Icon(ft.Icons.LIGHTBULB_CIRCLE, color=ft.Colors.AMBER_ACCENT),
                    ft.Column([
                        ft.Text("Start New Delegation", size=14, weight=ft.FontWeight.BOLD),
                        ft.Text(f"Available Balance: {sol_bal} SOL", size=12, color=ft.Colors.GREY_400)
                    ], spacing=2, expand=True),
                    ft.Icon(ft.Icons.CHEVRON_RIGHT, color=ft.Colors.GREY_400)
                ]),
                padding=12, bgcolor=ft.Colors.with_opacity(0.3, ft.Colors.BLUE_900), border_radius=8, ink=True,
                on_click=lambda _: asyncio.create_task(render_deposit_form(sol_bal))
            )
        )
        dashboard_view.controls.append(ft.Divider(height=1, color=ft.Colors.GREY_800))
        dashboard_view.controls.append(ft.Text("ACTIVE DELEGATIONS:", size=11, color=ft.Colors.GREY_500, weight=ft.FontWeight.BOLD))

        loading_ring = ft.Container(
            content=ft.ProgressRing(width=24, height=24),
            alignment=ft.Alignment(0, 0),
            padding=20
        )
        dashboard_view.controls.append(loading_ring)

        dlg = ft.AlertDialog(
            title=ft.Row([
                ft.Text("Solana Native Staking"),
                ft.IconButton(ft.Icons.CLOSE, on_click=lambda _: [setattr(dlg, "open", False), page.update()])
            ]),
            content=dashboard_view
        )

        page.overlay.append(dlg)
        dlg.open = True
        page.update()

        active_stakes = await async_fetch_stake_accounts(state["wallet_pubkey"])
        dashboard_view.controls.remove(loading_ring)

        if not active_stakes:
            dashboard_view.controls.append(
                ft.Text("No active stake accounts detected.", size=13, color=ft.Colors.GREY_500, italic=True)
            )
        else:
            for stk in active_stakes:
                def make_acc_callback(data_struct):
                    return lambda _: asyncio.create_task(render_management_form(data_struct, dlg))

                dashboard_view.controls.append(
                    ft.Container(
                        content=ft.Row([
                            ft.Icon(ft.Icons.ACCOUNT_BALANCE_WALLET_OUTLINED, color=ft.Colors.BLUE_400),
                            ft.Column([
                                ft.Text(f"{stk['address'][:6]}...{stk['address'][-6:]}", size=13, weight=ft.FontWeight.BOLD),
                                ft.Text(f"Validator: {stk['validator'][:5]}...{stk['validator'][-5:]}", size=11, color=ft.Colors.GREY_400)
                            ], spacing=1, expand=True),
                            ft.Icon(ft.Icons.CHEVRON_RIGHT, color=ft.Colors.GREY_400)
                        ]),
                        padding=10, bgcolor=ft.Colors.GREY_900, border_radius=6, ink=True,
                        on_click=make_acc_callback(stk)
                    )
                )
        page.update()

    async def render_deposit_form(available_sol):
        """Displays inputs to trigger your stake_sol backend with an embedded scanner view layer."""
        amount_input = ft.TextField(label="Amount to Stake (SOL)", value="0.0", keyboard_type=ft.KeyboardType.NUMBER, expand=True)
        validator_input = ft.TextField(label="Validator Vote Account Address", hint_text="Paste or Scan Vote1111... Address", expand=True)
        
        # Initialize local components for this specific dialog wrapper window
        deposit_camera_scan_block = ft.Column(controls=[], visible=False, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10)

        async def handle_validator_scanner(e):
            """Launches lens targeting validator address scanning selection rules."""
            await launch_deposit_lens_feed("transfer", "Step 1: Scan Validator Vote Address QR")

        async def launch_deposit_lens_feed(target_mode: str, status_text: str):
            """Swaps the view layer to show the centered camera feed layout box."""
            if state["is_scanning"]: 
                await stop_deposit_active_scanner()
            
            state["active_scan_target"] = target_mode
            state["is_processing"] = False
            state["signer_scan_done"].clear()

            camera_status_overlay_text.value = status_text.upper()
            camera_status_overlay_text.color = ft.Colors.GREEN_400 if target_mode == "signer" else ft.Colors.AMBER_400
            camera_container.content = ft.Stack([camera_viewfinder, camera_status_container])
            
            deposit_scan_ctrl_btn.on_click = lambda e: asyncio.create_task(toggle_deposit_scanner_hardware())
            deposit_scan_ctrl_btn.content = ft.Text("Start QR Scanner", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD)
            deposit_scan_ctrl_btn.bgcolor = ft.Colors.BLUE_700

            deposit_review_fields_container.visible = False
            deposit_camera_scan_block.controls = [camera_container, deposit_scan_ctrl_btn]
            deposit_camera_scan_block.visible = True
            deposit_dlg.update()

        async def toggle_deposit_scanner_hardware():
            """Toggles video hardware collection thread workers on and off."""
            if state["is_processing"]: 
                return
            if not state["is_scanning"]:
                state["is_processing"] = True
                state["cap"] = await asyncio.to_thread(cv2.VideoCapture, 0, cv2.CAP_AVFOUNDATION)
                
                if state["cap"] and state["cap"].isOpened():
                    state["cap"].set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                    state["cap"].set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                    state["is_scanning"] = True
                    
                    deposit_scan_ctrl_btn.content = ft.Text("Stop Camera Feed", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD)
                    deposit_scan_ctrl_btn.bgcolor = ft.Colors.RED_ACCENT_400
                    deposit_dlg.update()
                    
                    state["is_processing"] = False
                    asyncio.create_task(unified_camera_worker_with_deposit_hook())
                else:
                    state["cap"] = None
                    state["is_processing"] = False
                    camera_status_overlay_text.value = "HARDWARE ERROR DETECTED"
                    deposit_dlg.update()
            else:
                state["is_processing"] = True
                await stop_deposit_active_scanner()

        async def stop_deposit_active_scanner():
            """Drops lens connections and clears the dynamic view layout matrices."""
            state["is_scanning"] = False
            await asyncio.sleep(0.05)
            try:
                if state["cap"] is not None: 
                    state["cap"].release()
            except Exception as e: 
                print(f"[DEPOSIT HW ERR] {e}")
            finally: 
                state["cap"] = None
                state["is_processing"] = False
                
            deposit_camera_scan_block.visible = False
            deposit_camera_scan_block.controls = []
            deposit_review_fields_container.visible = True
            deposit_dlg.update()

        async def unified_camera_worker_with_deposit_hook():
            """Dedicated camera background stream poller for this specific deposit overlay."""
            while state["is_scanning"] and state["cap"] and state["cap"].isOpened():
                if not state["is_scanning"] or state["is_processing"]: 
                    break
                try:
                    success, frame = await asyncio.to_thread(state["cap"].read)
                    if not success: 
                        await asyncio.sleep(0.01)
                        continue
                        
                    h, w, _ = frame.shape
                    min_dim = min(h, w)
                    start_x = (w - min_dim) // 2
                    start_y = (h - min_dim) // 2
                    square_frame = frame[start_y:start_y+min_dim, start_x:start_x+min_dim]
                    small_frame = cv2.resize(square_frame, (320, 320))

                    _, encoded_buffer = cv2.imencode(".jpg", small_frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
                    base64_raw = base64.b64encode(encoded_buffer).decode("utf-8")
                    camera_viewfinder.src = f"data:image/jpeg;base64,{base64_raw}"
                    deposit_dlg.update()

                    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    data, _, _ = qr_decoder.detectAndDecode(gray_frame)
                    
                    if data and not state["is_processing"]:
                        clean_data = data.strip()
                        if clean_data:
                            state["is_processing"] = True
                            trigger_scan_success_beep()
                            
                            if state["active_scan_target"] == "transfer":
                                validator_input.value = clean_data
                                await stop_deposit_active_scanner()
                                break
                            elif state["active_scan_target"] == "signer":
                                state["signer_qr_str"] = clean_data
                                await stop_deposit_active_scanner()
                                state["active_scan_target"] = ""
                                state["signer_scan_done"].set() # Unlock execution thread safely
                                break
                except Exception: 
                    pass
                await asyncio.sleep(0.03)
        async def execute_staking_call(e):
            validator_vote_addr = validator_input.value.strip() if validator_input.value else ""
            amount_str = amount_input.value.strip() if amount_input.value else ""
            
            if not validator_vote_addr or not amount_str:
                await show_popup_message("Parameters Missing", "Please complete all target inputs.")
                return
            try: 
                requested_amount = float(amount_str)
            except ValueError: 
                return

            if requested_amount <= 0 or requested_amount > float(available_sol):
                await show_popup_message("Validation Error", "Invalid distribution boundary requested.")
                return

            # 1. Open the internal lens feed frame layout and wait for QR authentication completion
            await launch_deposit_lens_feed("signer", "Step 2: Scan SecretQR to Authorize Staking")
            await state["signer_scan_done"].wait()

            if not state["signer_qr_str"]:
                await show_popup_message("Signing Aborted", "No valid signature credentials provided.")
                return

            start_staking_btn.disabled = True
            deposit_dlg.update()

            try:
                # 2. Reconstruct keypair elements from scanned results
                formatted_input = state["signer_qr_str"][:-1] + f',"{state["wallet_qr_passcode"]}")'
                the_b58 = process_to_keypair(formatted_input, "LEDGER")
                signer = b58_to_signer(the_b58)

                await show_popup_message("Broadcasting", "Submitting your atomic staking allocation to the cluster...")

                # 3. Direct runtime execution straight to your backend stake module 
                sig = await asyncio.to_thread(
                    stake_sol,
                    amount_str,
                    validator_vote_addr,
                    state["wallet_pubkey"],
                    signer
                )
                
                print(f"[DEBUG] Staking transaction complete! Signature: {sig}")

                # 4. Close the modal on complete success
                deposit_dlg.open = False
                page.update()
                
                # FIX: String casting applied natively to prevent subscriptable signature crashes
                await show_popup_message("OK", f"Staking successful!\nSignature: {str(sig)[:12]}...")
                await refresh_wallet_data()
                await build_main_ui()
                
            except Exception as err:
                print(f"[CRITICAL DEBUG] Error inside execute_staking_call loop: {err}")
                start_staking_btn.disabled = False
                deposit_dlg.open = False
                page.update()
                await show_popup_message("Staking Failed", str(err))

        async def on_deposit_cancel_click(e):
            await stop_deposit_active_scanner()
            start_staking_btn.disabled = False
            deposit_dlg.open = False
            page.update()

        # Build local interface layout trees mirroring your SEND/MANAGE dialog structures
        scan_validator_btn = ft.Button(
            content=ft.Text("Scan QR", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD),
            bgcolor=ft.Colors.BLUE_700,
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=6)),
            on_click=handle_validator_scanner
        )
        
        validator_row = ft.Column(
            [validator_input, scan_validator_btn],
            spacing=5,
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH
        )

        deposit_review_fields_container = ft.Column([
            ft.Text(f"Available Balance: {available_sol} SOL", size=12, color=ft.Colors.GREY_400),
            ft.Text("Amount to Stake (SOL):", size=14, weight=ft.FontWeight.BOLD),
            amount_input,
            ft.Text("Validator Vote Account Address:", size=14, weight=ft.FontWeight.BOLD),
            validator_row
        ], tight=True, spacing=12, visible=True)

        deposit_scan_ctrl_btn = ft.Button(
            content=ft.Text("Start QR Scanner", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD),
            width=400, height=55, bgcolor=ft.Colors.BLUE_700
        )

        start_staking_btn = ft.Button(
            content=ft.Text("Scan SecretQR to Execute!", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD), 
            bgcolor=ft.Colors.RED_600, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)), 
            on_click=execute_staking_call
        )

        deposit_dlg = ft.AlertDialog(
            title=ft.Row([
                ft.Text("Delegate SOL Details"),
                ft.IconButton(ft.Icons.CLOSE, on_click=on_deposit_cancel_click)
            ]),
            content=ft.Column([deposit_review_fields_container, deposit_camera_scan_block], tight=True),
            actions=[ft.TextButton("Cancel", on_click=on_deposit_cancel_click), start_staking_btn],
            actions_alignment=ft.MainAxisAlignment.END
        )
        
        page.overlay.append(deposit_dlg)
        deposit_dlg.open = True
        page.update()

    async def render_management_form(stk, parent_dlg):
        """Displays selected stake account actions with an embedded scanner view layer layout."""
        is_inactive = stk['status'] in ["Initialized", "Deactivated"]
        action_label = "Withdraw Full Funds" if is_inactive else "Deactivate Stake"
        action_target = "withdraw" if is_inactive else "deactivate"

        # Initialize local components for this specific dialog wrapper window
        mgmt_camera_scan_block = ft.Column(controls=[], visible=False, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10)

        async def launch_mgmt_lens_feed():
            """Swaps the view layer to show the centered camera feed layout box."""
            if state["is_scanning"]: 
                await stop_mgmt_active_scanner()
            
            state["active_scan_target"] = "signer"
            state["is_processing"] = False
            state["signer_scan_done"].clear()

            camera_status_overlay_text.value = "SCAN SECRETQR TO AUTHORIZE DELEGATION REMOVAL"
            camera_status_overlay_text.color = ft.Colors.RED_400
            camera_container.content = ft.Stack([camera_viewfinder, camera_status_container])
            
            mgmt_scan_ctrl_btn.on_click = lambda e: asyncio.create_task(toggle_mgmt_scanner_hardware())
            mgmt_scan_ctrl_btn.content = ft.Text("Start Signature Scan", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD)
            mgmt_scan_ctrl_btn.bgcolor = ft.Colors.BLUE_700

            mgmt_review_fields_container.visible = False
            mgmt_camera_scan_block.controls = [camera_container, mgmt_scan_ctrl_btn]
            mgmt_camera_scan_block.visible = True
            mgmt_dialog.update()

        async def toggle_mgmt_scanner_hardware():
            """Toggles video hardware collection thread workers on and off."""
            if state["is_processing"]: 
                return
            if not state["is_scanning"]:
                state["is_processing"] = True
                state["cap"] = await asyncio.to_thread(cv2.VideoCapture, 0, cv2.CAP_AVFOUNDATION)
                
                if state["cap"] and state["cap"].isOpened():
                    state["cap"].set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                    state["cap"].set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                    state["is_scanning"] = True
                    
                    mgmt_scan_ctrl_btn.content = ft.Text("Stop Camera Feed", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD)
                    mgmt_scan_ctrl_btn.bgcolor = ft.Colors.RED_ACCENT_400
                    mgmt_dialog.update()
                    
                    state["is_processing"] = False
                    asyncio.create_task(unified_camera_worker_with_mgmt_hook())
                else:
                    state["cap"] = None
                    state["is_processing"] = False
                    camera_status_overlay_text.value = "HARDWARE ERROR DETECTED"
                    mgmt_dialog.update()
            else:
                state["is_processing"] = True
                await stop_mgmt_active_scanner()

        async def stop_mgmt_active_scanner():
            """Drops lens connections and clears the dynamic view layout matrices."""
            state["is_scanning"] = False
            await asyncio.sleep(0.05)
            try:
                if state["cap"] is not None: 
                    state["cap"].release()
            except Exception as e: 
                print(f"[MGMT HW ERR] {e}")
            finally: 
                state["cap"] = None
                state["is_processing"] = False
                
            mgmt_camera_scan_block.visible = False
            mgmt_camera_scan_block.controls = []
            mgmt_review_fields_container.visible = True
            mgmt_dialog.update()

        async def unified_camera_worker_with_mgmt_hook():
            """Dedicated camera background stream poller for this specific management overlay."""
            while state["is_scanning"] and state["cap"] and state["cap"].isOpened():
                if not state["is_scanning"] or state["is_processing"]: 
                    break
                try:
                    success, frame = await asyncio.to_thread(state["cap"].read)
                    if not success: 
                        await asyncio.sleep(0.01)
                        continue
                        
                    h, w, _ = frame.shape
                    min_dim = min(h, w)
                    start_x = (w - min_dim) // 2
                    start_y = (h - min_dim) // 2
                    square_frame = frame[start_y:start_y+min_dim, start_x:start_x+min_dim]
                    small_frame = cv2.resize(square_frame, (320, 320))

                    _, encoded_buffer = cv2.imencode(".jpg", small_frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
                    base64_raw = base64.b64encode(encoded_buffer).decode("utf-8")
                    camera_viewfinder.src = f"data:image/jpeg;base64,{base64_raw}"
                    mgmt_dialog.update()

                    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    data, _, _ = qr_decoder.detectAndDecode(gray_frame)
                    
                    if data and not state["is_processing"]:
                        clean_data = data.strip()
                        if clean_data:
                            state["is_processing"] = True
                            trigger_scan_success_beep()
                            state["signer_qr_str"] = clean_data
                            await stop_mgmt_active_scanner()
                            state["active_scan_target"] = ""
                            state["signer_scan_done"].set() 
                            break
                except Exception: 
                    pass
                await asyncio.sleep(0.03)
        async def handle_unstake_click(e):
            print(f"\n[DEBUG] Clicked '{action_label}'. Target: {stk['address']}")
            try:
                # 1. Open the internal lens feed frame layout and wait for QR authentication completion
                await launch_mgmt_lens_feed()
                await state["signer_scan_done"].wait()

                if not state["signer_qr_str"]:
                    raise Exception("Cryptographic signing action cancelled or empty data payload returned.")

                unstake_exec_btn.disabled = True
                mgmt_dialog.update()

                # 2. Reconstruct keypair elements from scanned results
                formatted_input = state["signer_qr_str"][:-1] + f',"{state["wallet_qr_passcode"]}")'
                the_b58 = process_to_keypair(formatted_input, "LEDGER")
                signer = b58_to_signer(the_b58)

                print(f"[DEBUG] Wallet Pubkey: {state['wallet_pubkey']}")
                print(f"[DEBUG] Executing backend thread call for '{action_target}'...")

                await show_popup_message("Broadcasting", f"Submitting {action_target.upper()} instruction payload...")

                # 3. Direct runtime execution straight to your backend unstake bytecode module 
                sig = await asyncio.to_thread(
                    unstake_sol,
                    stk['address'],
                    state["wallet_pubkey"],
                    signer,
                    action_target
                )
                
                print(f"[DEBUG] Transaction broadcast complete! Signature: {sig}")
                
                # 4. Collapse all open modal levels on total success
                mgmt_dialog.open = False
                parent_dlg.open = False
                page.update()
                
                await show_popup_message("OK", f"Action '{action_target.upper()}' complete!\nSignature: {str(sig)[:12]}...")
                await refresh_wallet_data()
                await build_main_ui()
                
            except Exception as err:
                print(f"[CRITICAL DEBUG] Error inside handle_unstake_click loop: {err}")
                unstake_exec_btn.disabled = False
                mgmt_dialog.open = False
                page.update()
                await show_popup_message("Unstake Error", str(err))

        async def on_mgmt_cancel_click(e):
            await stop_mgmt_active_scanner()
            unstake_exec_btn.disabled = False
            mgmt_dialog.open = False
            page.update()

        # Build local interface containers mirroring your SEND dialog logic structure
        mgmt_review_fields_container = ft.Column([
            ft.ListTile(title=ft.Text("Account Address"), subtitle=ft.Text(stk['address'], selectable=True, size=12)),
            ft.ListTile(title=ft.Text("Target Validator Node"), subtitle=ft.Text(stk['validator'], selectable=True, size=12)),
            ft.ListTile(title=ft.Text("Delegated Allocation Size"), subtitle=ft.Text(f"{stk['balance']:.4f} SOL", weight=ft.FontWeight.BOLD)),
            ft.ListTile(title=ft.Text("Current Status Layer"), subtitle=ft.Text(stk['status'].upper(), color=ft.Colors.GREEN_ACCENT if stk['status']=="Active" else ft.Colors.ORANGE_ACCENT))
        ], tight=True, spacing=5, visible=True)

        mgmt_scan_ctrl_btn = ft.Button(
            content=ft.Text("Start Signature Scan", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD),
            width=400, height=55, bgcolor=ft.Colors.BLUE_700
        )

        unstake_exec_btn = ft.Button(
            content=ft.Text(action_label, color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD),
            bgcolor=ft.Colors.GREEN_800 if is_inactive else ft.Colors.RED_800,
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=6)),
            on_click=handle_unstake_click 
        )

        mgmt_dialog = ft.AlertDialog(
            title=ft.Row([
                ft.Text("Manage Stake Account"), 
                ft.IconButton(ft.Icons.CLOSE, on_click=on_mgmt_cancel_click)
            ]),
            content=ft.Column([mgmt_review_fields_container, mgmt_camera_scan_block], tight=True),
            actions=[ft.TextButton("Cancel", on_click=on_mgmt_cancel_click), unstake_exec_btn],
            actions_alignment=ft.MainAxisAlignment.END
        )
        
        page.overlay.append(mgmt_dialog)
        mgmt_dialog.open = True
        page.update()

    async def build_main_ui():
        try:
            page.controls.clear()
            page.scroll = ft.ScrollMode.HIDDEN
            addr_str = str(state["wallet_pubkey"])

            account_info_block = ft.Container(
                content=ft.Column([
                    ft.Text("YOUR SOLANA WALLET ADDRESS:", size=12, color=ft.Colors.GREY_500, weight=ft.FontWeight.BOLD),
                    ft.Text(addr_str, size=12, color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER, selectable=True)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                padding=10, alignment=ft.Alignment(0, 0)
            )
            page.add(account_info_block)

            qr = qrcode.QRCode(version=1, box_size=10, border=1)
            qr.add_data(addr_str)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format="PNG")

            qr_base64 = base64.b64encode(buffer.getvalue()).decode()
            qr_widget = ft.Image(src=f"data:image/png;base64,{qr_base64}", width=160, height=160, fit=ft.BoxFit.CONTAIN)
            page.add(ft.Container(content=qr_widget, alignment=ft.Alignment(0, 0), padding=5))

            stake_dashboard_btn = ft.Container(
                content=ft.Button(
                    content=ft.Row([
                        ft.Icon(ft.Icons.TRACK_CHANGES_OUTLINED, size=20, color=ft.Colors.WHITE),
                        ft.Text("STAKE SOL NATIVELY (EARN REWARDS)", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE)
                    ], alignment=ft.MainAxisAlignment.CENTER),
                    width=400, height=55,
                    bgcolor=ft.Colors.DEEP_PURPLE_700,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
                    on_click=open_staking_dashboard
                ),
                padding=ft.Padding(bottom=10, top=5),
                alignment=ft.Alignment(0, 0)
            )
            page.add(stake_dashboard_btn)

            page.add(ft.Container(content=ft.Text("Select an Asset to Send:", size=16, weight=ft.FontWeight.BOLD), padding=ft.Padding(top=5), alignment=ft.Alignment(0, 0)))
            portfolio_list = ft.Column(scroll=ft.ScrollMode.ALWAYS, spacing=12, expand=True, horizontal_alignment=ft.CrossAxisAlignment.CENTER)

            for idx, token in enumerate(state["token_list"]):
                try:
                    if isinstance(token, dict):
                        t_name = str(token.get("name", "Unknown Token"))
                        t_mint = str(token.get("mint", ""))
                        t_bal = str(token.get("balance", "0.0"))
                    else:
                        t_name = "Token Asset"
                        t_mint = str(token)
                        t_bal = "0.0"

                    token_display_str = f"{t_name} Balance: {t_bal}"
                    def make_click_callback(name, mint, balance):
                        async def on_button_click(e):
                            asyncio.create_task(open_send_popup(name, mint, balance))
                        return on_button_click

                    token_btn = ft.FilledButton(
                        content=ft.Text(token_display_str, color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD),
                        width=400, height=65,
                        bgcolor=ft.Colors.BLUE_700 if t_name == "SOL" else ft.Colors.GREY_800,
                        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
                        on_click=make_click_callback(t_name, t_mint, t_bal)
                    )
                    portfolio_list.controls.append(token_btn)
                except Exception as inner_err:
                    print(f"[WARN] Error parsing token index {idx}: {inner_err}")
                    continue

            page.add(ft.Row([portfolio_list], alignment=ft.MainAxisAlignment.CENTER))

            async def on_sync_press(e):
                await refresh_wallet_data()
                await build_main_ui()

            bottom_nav = ft.Row([
                ft.Button(
                    content=ft.Text("Sync", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD),
                    width=110, height=50,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
                    on_click=on_sync_press
                ),
                ft.Button(
                    content=ft.Text("View on Solscan Explorer ↗", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD),
                    expand=True, height=50,
                    bgcolor=ft.Colors.PURPLE_700,
                    style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
                    on_click=lambda e: webbrowser.open(f"https://solscan.io/account/{addr_str}")
                )
            ], spacing=12)

            page.add(ft.Container(content=bottom_nav, padding=ft.Padding(top=15)))
            page.update()
        except Exception as critical_err:
            await show_popup_message("Layout Render Crash", f"Error Details:\n{str(critical_err)}")

    async def open_send_popup(token_name, token_mint, max_balance):
        print(f"[POPUP DEBUG] Executing inner fields builder for {token_name}...")

        # SECTION 1: COMPONENT AND CAMERA ENGINE DEFINITIONS (MUST BE FIRST)
        camera_scan_block = ft.Column(controls=[], visible=False, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10)

        state["transfer_to_address"] = ft.TextField(
            label="Recipient Address",
            hint_text="Paste or Scan Address",
            text_size=10, expand=True
        )

        def handle_max_click():
            amount_input.value = str(max_balance)
            if amount_input.page: amount_input.update()
            else: page.update()

        amount_input = ft.TextField(
            label="Amount to Send", expand=True, height=48,
            suffix=ft.TextButton("Max", style=ft.ButtonStyle(color=ft.Colors.BLUE), on_click=lambda e: handle_max_click())
        )

        # SECTION 2: CORE LENS LIFECYCLE HOOKS (PART 5 DEFINITIONS)
        async def launch_popup_lens_feed(target_mode: str, status_text: str):
            if state["is_scanning"]: await stop_popup_active_scanner()
            state["active_scan_target"] = target_mode
            state["is_processing"] = False
            state["signer_scan_done"].clear()

            camera_status_overlay_text.value = status_text.upper()
            camera_status_overlay_text.color = ft.Colors.GREEN_400 if target_mode == "signer" else ft.Colors.AMBER_400
            camera_container.content = ft.Stack([camera_viewfinder, camera_status_container])

            scan_ctrl_btn.on_click = lambda e: asyncio.create_task(toggle_popup_scanner_hardware())
            scan_ctrl_btn.content = ft.Text("Start QR Scanner", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD)
            scan_ctrl_btn.bgcolor = ft.Colors.BLUE_700

            review_fields_container.visible = False
            camera_scan_block.controls = [camera_container, scan_ctrl_btn]
            camera_scan_block.visible = True
            transfer_dialog.update()

        async def toggle_popup_scanner_hardware():
            if state["is_processing"]: return
            if not state["is_scanning"]:
                state["is_processing"] = True
                state["cap"] = await asyncio.to_thread(cv2.VideoCapture, 0, cv2.CAP_AVFOUNDATION)
                if state["cap"] and state["cap"].isOpened():
                    state["cap"].set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                    state["cap"].set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                    state["is_scanning"] = True
                    scan_ctrl_btn.content = ft.Text("Stop Camera Feed", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD)
                    scan_ctrl_btn.bgcolor = ft.Colors.RED_ACCENT_400
                    transfer_dialog.update()
                    state["is_processing"] = False
                    asyncio.create_task(unified_camera_worker_with_popup_hook())
                else:
                    state["cap"] = None
                    state["is_processing"] = False
                    camera_status_overlay_text.value = "HARDWARE ERROR DETECTED"
                    transfer_dialog.update()
            else:
                state["is_processing"] = True
                await stop_popup_active_scanner()

        async def stop_popup_active_scanner():
            state["is_scanning"] = False
            await asyncio.sleep(0.05)
            try:
                if state["cap"] is not None: state["cap"].release()
            except Exception as e: print(f"[POPUP HW ERR] {e}")
            finally: state["cap"] = None; state["is_processing"] = False
            camera_scan_block.visible = False
            camera_scan_block.controls = []
            review_fields_container.visible = True
            transfer_dialog.update()

        async def unified_camera_worker_with_popup_hook():
            while state["is_scanning"] and state["cap"] and state["cap"].isOpened():
                if not state["is_scanning"] or state["is_processing"]: break
                try:
                    success, frame = await asyncio.to_thread(state["cap"].read)
                    if not success: await asyncio.sleep(0.01); continue
                    h, w, _ = frame.shape; min_dim = min(h, w)
                    start_x = (w - min_dim) // 2; start_y = (h - min_dim) // 2
                    square_frame = frame[start_y:start_y+min_dim, start_x:start_x+min_dim]
                    small_frame = cv2.resize(square_frame, (320, 320))

                    _, encoded_buffer = cv2.imencode(".jpg", small_frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
                    base64_raw = base64.b64encode(encoded_buffer).decode("utf-8")
                    camera_viewfinder.src = f"data:image/jpeg;base64,{base64_raw}"
                    transfer_dialog.update()

                    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    data, _, _ = qr_decoder.detectAndDecode(gray_frame)
                    if data and not state["is_processing"]:
                        clean_data = data.strip()
                        if clean_data:
                            state["is_processing"] = True
                            trigger_scan_success_beep()
                            if state["active_scan_target"] == "transfer":
                                state["transfer_to_address"].value = clean_data
                                await stop_popup_active_scanner(); break
                            elif state["active_scan_target"] == "signer":
                                state["signer_qr_str"] = clean_data
                                await stop_popup_active_scanner()
                                state["signer_scan_done"].set(); break
                except Exception: pass
                await asyncio.sleep(0.03)

        # SECTION 3: INTERFACE ACTIONS AND EVENT CLICK HANDLERS (PART 6 DEFINITIONS)
        async def handle_recipient_scanner(e):
            await launch_popup_lens_feed("transfer", "Step 2: Scan Destination Address QR")

        async def handle_signer_scanner_popup():
            await launch_popup_lens_feed("signer", "Step 3: Scan SecretQR to Authorize")
            await state["signer_scan_done"].wait()

        scan_addr_btn = ft.Button(
            content=ft.Text("Scan QR", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD),
            bgcolor=ft.Colors.BLUE_700,
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=6)),
            on_click=handle_recipient_scanner
        )
        recipient_row = ft.Column(
            [state["transfer_to_address"], scan_addr_btn],
            spacing=5,
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH
        )

        async def execute_blockchain_transfer(e):
            target_address = state["transfer_to_address"].value.strip() if state["transfer_to_address"].value else ""
            amount_str = amount_input.value.strip() if amount_input.value else ""
            if not target_address or not amount_str:
                await show_popup_message("Parameters Missing", "Please complete all target inputs.")
                return
            try: requested_amount = float(amount_str)
            except ValueError: return

            if requested_amount <= 0 or requested_amount > float(max_balance):
                await show_popup_message("Validation Error", "Invalid distribution boundary requested.")
                return

            send_exec_btn.disabled = True
            transfer_dialog.update()

            try:
                await handle_signer_scanner_popup()
                if state["signer_qr_str"]:
                    formatted_input = state["signer_qr_str"][:-1] + f',"{state["wallet_qr_passcode"]}")'
                    the_b58 = process_to_keypair(formatted_input, "LEDGER")
                    signer = b58_to_signer(the_b58)

                    if token_name == "SOL":
                        tx_id = await asyncio.to_thread(
                            transfer_sol, target_address, requested_amount, signer.pubkey(), signer
                        )
                    else:
                        tx_id = await asyncio.to_thread(
                            transfer_spl_token, target_address, token_mint, requested_amount, signer.pubkey(), signer
                        )
                    if tx_id:
                        tx_url = f"https://solscan.io/tx/{tx_id}"
                        webbrowser.open(tx_url)

                transfer_dialog.open = False
                page.update()
                await refresh_wallet_data()
                await build_main_ui()
            except Exception as blockchain_err:
                send_exec_btn.disabled = False
                transfer_dialog.update()
                await show_popup_message("Execution Failure", str(blockchain_err))

        async def on_cancel_click(e):
            await stop_popup_active_scanner()
            send_exec_btn.disabled = False
            transfer_dialog.open = False
            page.update()

        # SECTION 4: DIALOG VISUAL ASSEMBLY AND MOUNTING
        review_fields_container = ft.Column([
            ft.Text(f"Asset: {token_name}", size=20, weight=ft.FontWeight.BOLD),
            ft.Text(f"Mint: {token_mint if token_mint else 'N/A'}", size=10, color=ft.Colors.GREY_400),
            ft.Text(f"Available: {max_balance}", size=14, color=ft.Colors.GREEN_400, weight=ft.FontWeight.BOLD),
            ft.Text("Recipient Address:", size=12, weight=ft.FontWeight.BOLD),
            recipient_row, ft.Text("Amount to Send:", size=14, weight=ft.FontWeight.BOLD), amount_input
        ], tight=True, spacing=12, visible=True)

        send_exec_btn = ft.Button(
            content=ft.Text("Scan SecretQR to Execute!", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD),
            bgcolor=ft.Colors.RED_600, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
            on_click=execute_blockchain_transfer
        )

        scan_ctrl_btn = ft.Button(
            content=ft.Text("Start QR Scanner", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD),
            width=400, height=55, bgcolor=ft.Colors.BLUE_700
        )

        transfer_dialog = ft.AlertDialog(
            title=ft.Text("SEND", weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_400),
            content=ft.Column([review_fields_container, camera_scan_block], tight=True),
            actions=[ft.TextButton("Cancel", on_click=on_cancel_click), send_exec_btn],
            actions_alignment=ft.MainAxisAlignment.END
        )
        page.overlay.append(transfer_dialog)
        transfer_dialog.open = True
        page.update()

    # --- CAM REGION OVERLAY STATUS BOX LABELS ---
    async def show_popup_message(title_text, message_text):
        async def close_dialog(e):
            alert_dialog.open = False
            page.update()
        alert_dialog = ft.AlertDialog(
            title=ft.Text(title_text, weight=ft.FontWeight.BOLD),
            content=ft.Text(message_text, size=16),
            actions=[ft.TextButton("OK", on_click=close_dialog)]
        )
        page.dialog = alert_dialog
        alert_dialog.open = True
        page.update()

    async def open_create_qr_popup(e):
        """Displays an interactive modal to encrypt text fields and display the generated QR code matrix."""
        secret_text_input = ft.TextField(
            label="Your Secret Text",
            hint_text="Enter key, seed phrase, or secret string details",
            text_size=14
        )
        passcode_input_field = ft.TextField(
            label="Your Stong Passcode",
            password=True,
            can_reveal_password=True,
            keyboard_type=ft.KeyboardType.NUMBER,
            text_size=14
        )

        async def process_and_generate_qr(e):
            secret_val = secret_text_input.value.strip() if secret_text_input.value else ""
            passcode_val = passcode_input_field.value.strip() if passcode_input_field.value else ""

            if not secret_val or not passcode_val:
                await show_popup_message("Input Missing", "Both the Secret Text and Passcode fields are mandatory.")
                return

            try:
                # Call your existing backend function to retrieve the transformed text data
                returned_encrypted_str = encrypt(secret_val, passcode_val)

                # Generate the in-memory QR matrix structure using the exact returned text string value
                qr = qrcode.QRCode(version=1, box_size=10, border=1)
                qr.add_data(returned_encrypted_str)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")

                buffer = BytesIO()
                img.save(buffer, format="PNG")
                qr_base64 = base64.b64encode(buffer.getvalue()).decode()

                # FIXED: Close the input dialog prompt sheet natively using the working open=False rule
                create_dialog.open = False
                page.update()

                qr_display_dialog = ft.AlertDialog(
                    title=ft.Text("Your Generated Secret QR Code", weight=ft.FontWeight.BOLD),
                    content=ft.Column([
                        # Scaled to fill out maximum display window boundary space safely without layout clipping
                        ft.Image(src=f"data:image/png;base64,{qr_base64}", width=300, height=300, fit=ft.BoxFit.CONTAIN),
                        ft.Divider(height=10, color=ft.Colors.TRANSPARENT),
                        ft.Text("Encrypted Payload Output String Data:", size=11, color=ft.Colors.GREY_500, weight=ft.FontWeight.BOLD),
                        # Displaying the raw returned text payload data in a smaller, selectable font line track
                        ft.Text(returned_encrypted_str, size=10, color=ft.Colors.WHITE, text_align=ft.TextAlign.CENTER, selectable=True)
                    ], tight=True, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    # FIXED: Close button lambda statement maps directly onto the working open=False property
                    actions=[
                        ft.TextButton(
                            content=ft.Text("OK", color=ft.Colors.BLUE_400, weight=ft.FontWeight.BOLD),
                            on_click=lambda _: setattr(qr_display_dialog, "open", False) or page.update()
                        )
                    ],
                    actions_alignment=ft.MainAxisAlignment.CENTER
                )

                # FIXED: Safely append the final presentation window onto the working overlay layout
                page.overlay.append(qr_display_dialog)
                qr_display_dialog.open = True
                page.update()

            except Exception as qr_err:
                await show_popup_message("Encryption Error", f"Failed to calculate matrix string output: {str(qr_err)}")

        create_dialog = ft.AlertDialog(
            title=ft.Text("Create New SecretQR Code", weight=ft.FontWeight.BOLD),
            content=ft.Column([
                secret_text_input,
                passcode_input_field
            ], tight=True, spacing=15),
            actions=[
                # FIXED: Cancel button lambda statement updated to use working .open = False rule to eliminate the AttributeError
                ft.TextButton(
                    content=ft.Text("Cancel", color=ft.Colors.GREY_400),
                    on_click=lambda _: setattr(create_dialog, "open", False) or page.update()
                ),
                ft.TextButton(
                    content=ft.Text("Create Secret QR Code", color=ft.Colors.BLUE_400, weight=ft.FontWeight.BOLD),
                    on_click=process_and_generate_qr
                )
            ],
            actions_alignment=ft.MainAxisAlignment.END
        )

        # Use your verified working overlay display method path exclusively
        page.overlay.append(create_dialog)
        create_dialog.open = True
        page.update()


    camera_status_overlay_text = ft.Text(
        value="STEP 1: INITIAL PASS IDENTITY SCANNER ACTIVE",
        size=11, weight=ft.FontWeight.BOLD,
        color=ft.Colors.BLUE_400, text_align=ft.TextAlign.CENTER
    )

    # Swapped ft.alignment.center to ft.Alignment(0, 0)
    camera_status_container = ft.Container(
        content=camera_status_overlay_text,
        bgcolor=ft.Colors.with_opacity(0.85, ft.Colors.BLACK),
        padding=8, border_radius=4, margin=10,
        alignment=ft.Alignment(0, 0), height=35, width=300
    )

    header_lbl = ft.Text(
        "Semaj's SOLANA WALLET",
        size=24,
        weight=ft.FontWeight.BOLD,
        text_align=ft.TextAlign.CENTER
    )

    qr_status_label = ft.Text(
        "To unlock your wallet\n\nTap 'Start QR Scanner'\n\nto scan a Semaj's Secret QR Code",
        size=18,
        color=ft.Colors.GREY_400,
        text_align=ft.TextAlign.CENTER
    )

    # Swapped out the old 'ImageFit' enum path to modern 'BoxFit'
    camera_viewfinder = ft.Image(
        src="memory://camera_feed",
        width=320,
        height=320,
        fit=ft.BoxFit.COVER
    )

    camera_container = ft.Container(
        content=qr_status_label,
        alignment=ft.Alignment(0, 0),
        height=320,
        border=ft.Border.all(1, ft.Colors.GREY_800),
        border_radius=12,
        padding=15
    )

    scan_ctrl_btn = ft.Button(
        content=ft.Text("Start QR Scanner", color=ft.Colors.WHITE, size=16, weight=ft.FontWeight.BOLD),
        width=400,
        height=55,
        bgcolor=ft.Colors.BLUE_700,
        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
        on_click=toggle_login_scanner
    )

    password_input = ft.TextField(
        label="Enter Passcode",
        password=True,
        can_reveal_password=True,
        width=400,
        content_padding=15,
        text_size=20
    )

    proceed_btn = ft.Button(
        content=ft.Text("Proceed & Unlock Wallet", color=ft.Colors.WHITE, size=18, weight=ft.FontWeight.BOLD),
        width=400,
        height=60,
        bgcolor=ft.Colors.GREEN_700,
        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
        on_click=handle_wallet_unlock
    )

    # New action control button mapping layout link configuration parameters
    create_qr_btn = ft.Button(
        content=ft.Text("Create New SecretQR Code", color=ft.Colors.BLUE_400, size=16, weight=ft.FontWeight.BOLD),
        width=400,
        height=50,
        bgcolor=ft.Colors.TRANSPARENT,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=8),
            side=ft.BorderSide(1, ft.Colors.BLUE_900) # Outlined visual look layout style element link
        ),
        on_click=open_create_qr_popup
    )

    # Multi-line clean format presentation tree structure
    page.add(
        ft.Container(
            padding=10,
            alignment=ft.Alignment(0, 0),
            content=ft.Column(
                spacing=15,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Container(content=header_lbl, alignment=ft.Alignment(0, 0), padding=10),
                    camera_container,
                    scan_ctrl_btn,
                    # ft.Text("Enter Passcode:", size=14, color=ft.Colors.GREY_400),
                    password_input,
                    proceed_btn,
                    ft.Divider(height=10, color=ft.Colors.TRANSPARENT),
                    create_qr_btn
                ]
            )
        )
    )
    page.update()


if __name__ == '__main__':
    ft.run(main=main)

